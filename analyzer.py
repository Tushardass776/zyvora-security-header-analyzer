def analyze_headers(headers):
    """
    Analyze HTTP security headers and calculate a security score.

    The analyzer checks six headers. For three headers it also checks
    whether the detected value matches a commonly recommended value.
    """

    normalized_headers = {
        name.lower(): value.strip()
        for name, value in headers.items()
    }

    security_headers = [
        {
            "name": "Content-Security-Policy",
            "key": "content-security-policy",
            "points": 25,
            "priority_rank": 1,
            "plain_name": "Content loading protection",
            "risk": (
                "Without CSP, the browser has fewer restrictions on where "
                "scripts and other resources can come from."
            ),
            "action": (
                "Ask whoever manages the website or web server to add a "
                "Content-Security-Policy. Start with a policy based on the "
                "resources the site actually uses rather than copying a "
                "strict policy blindly."
            ),
            "solution": (
                "Content-Security-Policy: default-src 'self'; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'self';"
            ),
            "solution_note": (
                "This is only a starter policy. Real websites often need "
                "additional sources for scripts, styles, images, fonts, APIs, "
                "analytics, payments, or other services. Test CSP carefully "
                "before enforcing it."
            ),
            "practical_url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            "technical_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
        },
        {
            "name": "Strict-Transport-Security",
            "key": "strict-transport-security",
            "points": 20,
            "priority_rank": 2,
            "plain_name": "HTTPS-only protection",
            "risk": (
                "Without HSTS, the browser is not told to remember that the "
                "website should always use HTTPS."
            ),
            "action": (
                "First make sure the complete website works correctly over "
                "HTTPS. Then configure the server to send HSTS on HTTPS "
                "responses. Only use includeSubDomains when the relevant "
                "subdomains also support HTTPS."
            ),
            "solution": (
                "Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ),
            "solution_note": (
                "Do not add includeSubDomains or preload until you are sure "
                "the domain and its relevant subdomains can remain HTTPS-only. "
                "A wrong HSTS configuration can make a site inaccessible."
            ),
            "practical_url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            "technical_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security",
        },
        {
            "name": "X-Content-Type-Options",
            "key": "x-content-type-options",
            "points": 15,
            "priority_rank": 4,
            "plain_name": "File-type protection",
            "risk": (
                "Without the recommended setting, browsers may have more "
                "freedom to interpret a response instead of strictly following "
                "the server's declared content type."
            ),
            "action": (
                "Configure the website server to send the following header. "
                "This is normally a simple server-level change."
            ),
            "solution": "X-Content-Type-Options: nosniff",
            "solution_note": (
                "Also make sure the website sends the correct Content-Type "
                "for its files. The nosniff setting works together with correct "
                "content types."
            ),
            "practical_url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "technical_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options",
        },
        {
            "name": "X-Frame-Options",
            "key": "x-frame-options",
            "points": 15,
            "priority_rank": 3,
            "plain_name": "Clickjacking protection",
            "risk": (
                "Without a suitable frame policy, attackers may be able to "
                "place a page inside another website and trick a user into "
                "clicking something."
            ),
            "action": (
                "If the site never needs to be embedded in another site, use "
                "DENY. If pages on the same site legitimately need to frame it, "
                "use SAMEORIGIN. For modern browsers, CSP frame-ancestors can "
                "provide more detailed control."
            ),
            "solution": "X-Frame-Options: DENY",
            "solution_note": (
                "Use SAMEORIGIN instead if legitimate same-site framing is "
                "required. Do not use the obsolete ALLOW-FROM value."
            ),
            "practical_url": "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            "technical_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options",
        },
        {
            "name": "Referrer-Policy",
            "key": "referrer-policy",
            "points": 15,
            "priority_rank": 5,
            "plain_name": "Referrer privacy",
            "risk": (
                "A permissive referrer policy can share more information about "
                "the page a visitor came from than the website needs to share."
            ),
            "action": (
                "For a straightforward privacy-conscious default, use "
                "strict-origin-when-cross-origin unless the website has a "
                "specific reason to use another policy."
            ),
            "solution": "Referrer-Policy: strict-origin-when-cross-origin",
            "solution_note": (
                "The best policy depends on how the website uses referrer "
                "information. no-referrer is more restrictive, while "
                "same-origin keeps the full referrer for same-site requests."
            ),
            "practical_url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "technical_url": "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Referrer_policy",
        },
        {
            "name": "Permissions-Policy",
            "key": "permissions-policy",
            "points": 10,
            "priority_rank": 6,
            "plain_name": "Browser-feature permissions",
            "risk": (
                "Without an explicit policy, the website has less control over "
                "which browser features may be available to pages and embedded "
                "content."
            ),
            "action": (
                "List the browser features the website actually needs, then "
                "disable unnecessary features. Start conservatively and test "
                "the website before adding more restrictions."
            ),
            "solution": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "solution_note": (
                "Do not paste this example blindly if the website legitimately "
                "needs camera, microphone, location, or another browser feature."
            ),
            "practical_url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "technical_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Permissions_Policy",
        },
    ]

    results = []
    score = 0

    for header in security_headers:
        key = header["key"]
        points = header["points"]

        if key not in normalized_headers:
            results.append({
                **header,
                "status": "Missing",
                "value": "",
                "points": 0,
                "max_points": points,
            })
            continue

        value = normalized_headers[key]

        if key == "x-content-type-options":
            valid = value.lower() == "nosniff"
        elif key == "x-frame-options":
            valid = value.upper() in ["DENY", "SAMEORIGIN"]
        elif key == "referrer-policy":
            strong_policies = [
                "no-referrer",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
            ]
            valid = value.lower() in strong_policies
        else:
            valid = True

        status = "Present" if valid else "Weak"
        earned_points = points if valid else 0
        score += earned_points

        results.append({
            **header,
            "status": status,
            "value": value,
            "points": earned_points,
            "max_points": points,
        })

    return results, score
