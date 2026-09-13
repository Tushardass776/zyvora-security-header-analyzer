import ipaddress
import os
import socket
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

import urllib3
from flask import Flask, render_template, request

from analyzer import analyze_headers

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

# Keep the public scanner deliberately small and bounded.
MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 5
CONNECT_TIMEOUT = 4.0
READ_TIMEOUT = 6.0
SCAN_DEADLINE = 12.0

# Disable urllib3 warnings only where they are relevant to our controlled use.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BLOCKED_RESPONSE_HEADERS = {
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "cookie",
}


def get_grade(score):
    if score >= 95:
        return "S", "Exceptional"
    if score >= 85:
        return "A", "Strong"
    if score >= 70:
        return "B", "Adequate"
    if score >= 50:
        return "C", "Attention Required"
    if score >= 25:
        return "D", "Weak"
    return "E", "Critical"


def build_summary(results):
    verified = sum(x["status"] == "Present" for x in results)
    review = sum(x["status"] == "Weak" for x in results)
    missing = sum(x["status"] == "Missing" for x in results)
    issues = [x for x in results if x["status"] != "Present"]
    priority = sorted(
        issues,
        key=lambda x: (x.get("priority_rank", 99), -x["max_points"]),
    )
    score = sum(x["points"] for x in results)

    if not issues:
        headline = "No header problems were found."
        message = (
            "All six protections checked by this tool were found and passed. "
            "That is a strong result for security headers. It does not prove "
            "the entire website is secure, but no header fix is recommended here."
        )
    elif score >= 70:
        headline = (
            "The website has a good security baseline, "
            "with a few improvements to make."
        )
        message = (
            f"We verified {verified} of {len(results)} protections. {len(issues)} "
            "item(s) need attention. Start with the fixes shown below; each one "
            "explains what the problem means and gives you a practical "
            "configuration example."
        )
    elif score >= 40:
        headline = (
            "The website has some protection, "
            "but important gaps remain."
        )
        message = (
            f"We verified {verified} of {len(results)} protections. {len(issues)} "
            "item(s) need attention. You do not need to understand HTTP headers "
            "first — the fixes below explain what to change and why."
        )
    else:
        headline = (
            "Several important website protections are "
            "missing or need correction."
        )
        message = (
            f"Only {verified} of {len(results)} protections were verified. "
            "This does not mean the website is hacked. It means this tool "
            "found missing or weak browser-level protections. Work through "
            "the fixes from top to bottom and scan the website again after "
            "making changes."
        )

    return {
        "verified": verified,
        "review": review,
        "missing": missing,
        "issue_count": len(issues),
        "headline": headline,
        "message": message,
        "priority_items": priority[:3],
    }


def _is_public_ip(value):
    """Return True only for globally routable IP addresses."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    # is_global excludes private, loopback, link-local, multicast,
    # reserved, unspecified and other non-public ranges.
    # This also blocks cloud metadata/link-local addresses such as
    # 169.254.169.254.
    return ip.is_global


def _resolve_public_host(hostname):
    """Resolve a hostname and return safe public IPs only.

    Rejecting a hostname if ANY returned address is non-public prevents
    a mixed public/private DNS answer from becoming an SSRF bypass.
    """
    hostname = hostname.rstrip(".").lower()

    if not hostname:
        raise ValueError("Please enter a valid hostname.")

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError(
            "Localhost and local network targets are not allowed."
        )

    # Handle literal IP addresses.
    try:
        literal = ipaddress.ip_address(hostname)

        if not _is_public_ip(str(literal)):
            raise ValueError(
                "Private or reserved IP addresses are not allowed."
            )

        return [str(literal)]

    except ValueError as exc:
        # A normal hostname also raises ValueError from ip_address().
        # Preserve our explicit security rejection for IP literals.
        if "not allowed" in str(exc):
            raise

    try:
        infos = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            "The target hostname could not be resolved."
        ) from exc

    addresses = sorted(
        {info[4][0] for info in infos},
        key=lambda address: (
            ipaddress.ip_address(address).version,
            address,
        ),
    )

    if not addresses:
        raise ValueError(
            "The target hostname did not resolve to an address."
        )

    # IMPORTANT:
    # Every resolved address must be public. This prevents an attacker
    # from using a hostname that resolves to both public and private IPs.
    if any(not _is_public_ip(address) for address in addresses):
        raise ValueError(
            "The target resolves to a private or reserved network address."
        )

    return addresses


def _validate_target_url(raw_url):
    """Validate a user-controlled target before making an outbound request."""
    raw_url = (raw_url or "").strip()

    if not raw_url:
        raise ValueError("Please enter a website address.")

    if len(raw_url) > MAX_URL_LENGTH:
        raise ValueError("The website address is too long.")

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    try:
        parsed = urlsplit(raw_url)
    except ValueError as exc:
        raise ValueError(
            "The website address is not valid."
        ) from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(
            "Only HTTP and HTTPS websites are allowed."
        )

    if not parsed.hostname:
        raise ValueError("Please enter a valid hostname.")

    if parsed.username or parsed.password:
        raise ValueError(
            "URLs containing usernames or passwords are not allowed."
        )

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            "The target uses an invalid port."
        ) from exc

    if port is not None and port not in {80, 443}:
        raise ValueError(
            "Only standard HTTP and HTTPS ports are allowed."
        )

    # Validate DNS/IP before making any outbound connection.
    _resolve_public_host(parsed.hostname)

    # Normalize the URL while preserving path/query.
    # Fragments are never sent to the server.
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _safe_response_headers(headers):
    """Return response headers safe to display to the scanner user."""
    safe = {}

    for name, value in headers.items():
        if name.lower() in BLOCKED_RESPONSE_HEADERS:
            continue

        # Keep the UI bounded even if a target returns unusually large values.
        safe[str(name)] = str(value)[:8192]

    return safe


def fetch_headers_safely(start_url):
    """Fetch only response headers with SSRF and redirect protections.

    Every DNS result is validated as public before connecting.

    For hosts with multiple public IP addresses, the scanner tries each
    validated address until one responds. HTTPS connections still use the
    original hostname for SNI and certificate verification.

    Redirects are manually followed so every new destination goes through
    the same SSRF validation.
    """
    current_url = _validate_target_url(start_url)
    redirects = 0

    deadline = time.monotonic() + SCAN_DEADLINE

    while True:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            raise TimeoutError

        parsed = urlsplit(current_url)

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Please enter a valid hostname.")

        port = parsed.port or (
            443 if parsed.scheme == "https" else 80
        )

        # Resolve immediately before connecting.
        # This reduces DNS-rebinding risk.
        addresses = _resolve_public_host(hostname)

        # Prefer IPv4 first because some serverless environments have
        # more reliable IPv4 outbound connectivity.
        addresses = sorted(
            addresses,
            key=lambda address: (
                0 if ipaddress.ip_address(address).version == 4 else 1,
                address,
            ),
        )

        path = parsed.path or "/"

        if parsed.query:
            path += "?" + parsed.query

        common_headers = {
            "Host": hostname,
            "User-Agent": "Zyvora-Security-Header-Analyzer/1.0",
            "Accept": "*/*",
            "Connection": "close",
        }

        last_error = None
        redirect_url = None

        # Try every validated public IP address.
        for ip in addresses:
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                raise TimeoutError

            timeout = urllib3.Timeout(
                connect=min(CONNECT_TIMEOUT, remaining),
                read=min(READ_TIMEOUT, remaining),
            )

            pool = None

            try:
                if parsed.scheme == "https":
                    pool = urllib3.HTTPSConnectionPool(
                        ip,
                        port=port,
                        timeout=timeout,
                        maxsize=1,
                        cert_reqs="CERT_REQUIRED",
                        assert_hostname=hostname,
                        server_hostname=hostname,
                    )
                else:
                    pool = urllib3.HTTPConnectionPool(
                        ip,
                        port=port,
                        timeout=timeout,
                        maxsize=1,
                    )

                response = pool.request(
                    "GET",
                    path,
                    headers=common_headers,
                    preload_content=False,
                    redirect=False,
                    retries=False,
                )

                # Handle redirects ourselves.
                if response.status in {
                    301,
                    302,
                    303,
                    307,
                    308,
                }:
                    location = response.headers.get("Location")

                    response.release_conn()
                    pool.close()

                    if not location:
                        safe_headers = _safe_response_headers(
                            response.headers
                        )

                        return (
                            current_url,
                            int(response.status),
                            safe_headers,
                        )

                    redirect_url = urljoin(
                        current_url,
                        location,
                    )

                    break

                # We only need headers.
                # Never download the response body.
                safe_headers = _safe_response_headers(
                    response.headers
                )

                status_code = int(response.status)

                response.release_conn()
                pool.close()

                return (
                    current_url,
                    status_code,
                    safe_headers,
                )

            except urllib3.exceptions.SSLError as exc:
                last_error = exc

                if pool is not None:
                    pool.close()

                # Try another validated public IP.
                continue

            except (
                urllib3.exceptions.ConnectTimeoutError,
                urllib3.exceptions.ReadTimeoutError,
            ) as exc:
                last_error = exc

                if pool is not None:
                    pool.close()

                # One CDN/edge IP may be unavailable from Vercel.
                # Try the next validated address.
                continue

            except urllib3.exceptions.HTTPError as exc:
                last_error = exc

                if pool is not None:
                    pool.close()

                continue

            except OSError as exc:
                last_error = exc

                if pool is not None:
                    pool.close()

                continue

        # A redirect was received.
        if redirect_url:
            if redirects >= MAX_REDIRECTS:
                raise ValueError(
                    "The website redirected too many times."
                )

            # The redirect target is fully validated before connection.
            current_url = _validate_target_url(
                redirect_url
            )

            redirects += 1
            continue

        # Every validated IP failed.
        if isinstance(
            last_error,
            (
                urllib3.exceptions.ConnectTimeoutError,
                urllib3.exceptions.ReadTimeoutError,
            ),
        ):
            raise TimeoutError from last_error

        if isinstance(
            last_error,
            urllib3.exceptions.SSLError,
        ):
            raise ValueError(
                "The website's HTTPS certificate could not be verified."
            ) from last_error

        if last_error is not None:
            raise ConnectionError(
                "Could not connect to the website."
            ) from last_error

        raise ConnectionError(
            "Could not retrieve the website response headers."
        )


@app.after_request
def add_security_headers(response):
    """Harden Zyvora's own HTTP responses."""
    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff",
    )

    response.headers.setdefault(
        "X-Frame-Options",
        "DENY",
    )

    response.headers.setdefault(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
    )

    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    )

    response.headers.setdefault(
        "Cross-Origin-Opener-Policy",
        "same-origin",
    )

    response.headers.setdefault(
        "Cross-Origin-Resource-Policy",
        "same-origin",
    )

    response.headers.setdefault(
        "X-DNS-Prefetch-Control",
        "off",
    )

    response.headers.setdefault(
        "Cache-Control",
        "no-store",
    )

    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "connect-src 'self'",
    )

    # HSTS is safe only when this deployment is actually served over HTTPS.
    # Vercel production deployments are HTTPS, while local HTTP development
    # is not.
    if request.is_secure or os.getenv("VERCEL") == "1":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

    return response


@app.route("/", methods=["GET", "POST"])
def index():
    url = ""
    headers = {}
    status_code = None
    error = None
    security_results = []
    security_score = None
    grade = None
    grade_label = None
    security_summary = None

    if request.method == "POST":
        # Small form payload limit; this endpoint never needs a large body.
        raw_url = request.form.get("url", "").strip()
        url = raw_url

        try:
            final_url, status_code, headers = fetch_headers_safely(
                raw_url
            )

            url = final_url

            security_results, security_score = analyze_headers(
                headers
            )

            grade, grade_label = get_grade(
                security_score
            )

            security_summary = build_summary(
                security_results
            )

        except TimeoutError:
            error = "The website took too long to respond."

        except ValueError as exc:
            error = str(exc)

        except ConnectionError as exc:
            error = str(exc)

        except Exception:
            # Do not expose internal exception details to a public user.
            error = (
                "The scan could not be completed. "
                "Please check the website address and try again."
            )

    return render_template(
        "index.html",
        url=url,
        headers=headers,
        status_code=status_code,
        error=error,
        security_results=security_results,
        security_score=security_score,
        grade=grade,
        grade_label=grade_label,
        security_summary=security_summary,
    )


if __name__ == "__main__":
    # Never enable Flask debug mode in a deployed environment.
    app.run(debug=False)
