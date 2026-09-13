# ZYVORA — Security Header Analyzer

> **Security Made Clear**

ZYVORA is a web-based security header analyzer that checks a website's HTTP response headers for important browser security protections.

The application allows a user to enter a website URL, retrieves its response headers, analyzes six important security headers, and generates a security score, grade, explanations, and recommended fixes.

## Live Demo

**Live Application:**  
https://zyvora-security-header-analyzer.vercel.app

---

## Project Overview

Modern websites use HTTP security headers to control browser behavior and reduce common web security risks.

ZYVORA provides a simple interface that:

1. Accepts a website URL.
2. Validates the target URL.
3. Safely retrieves the website's HTTP response headers.
4. Checks six important security headers.
5. Calculates a security score out of 100.
6. Assigns a security grade.
7. Explains missing or weak protections in simple language.
8. Provides practical recommendations and technical references.

The goal is to make website security-header analysis easier to understand without requiring users to manually inspect browser developer tools or HTTP responses.

---

## Features

### Security Header Analysis

ZYVORA checks the following six HTTP security headers:

| Security Header | Weight |
|---|---:|
| Content-Security-Policy | 25 |
| Strict-Transport-Security | 20 |
| X-Content-Type-Options | 15 |
| X-Frame-Options | 15 |
| Referrer-Policy | 15 |
| Permissions-Policy | 10 |
| **Total** | **100** |

### Security Score

Each security header contributes to an overall score from **0 to 100**.

| Score | Grade | Meaning |
|---:|:---:|---|
| 95–100 | S | Exceptional |
| 85–94 | A | Strong |
| 70–84 | B | Adequate |
| 50–69 | C | Attention Required |
| 25–49 | D | Weak |
| 0–24 | E | Critical |

### User-Friendly Results

The report provides:

- Plain-language explanations
- Security impact
- Recommended actions
- Practical solution examples
- Technical documentation references
- Raw response headers
- Overall security score and grade

---

## Security Checks

### 1. Content-Security-Policy

Helps control which resources a browser is allowed to load and can reduce the impact of certain content-injection attacks.

ZYVORA checks whether the header is present.

### 2. Strict-Transport-Security

Also known as HSTS.

It instructs browsers to use HTTPS when communicating with the website.

ZYVORA checks whether the header is present.

### 3. X-Content-Type-Options

Helps prevent browsers from MIME-sniffing resources.

ZYVORA considers the header strong when it contains:

```text
nosniff
```

### 4. X-Frame-Options

Helps control whether a page can be loaded inside a frame.

ZYVORA considers the following values strong:

```text
DENY
SAMEORIGIN
```

### 5. Referrer-Policy

Controls how much referrer information is sent when navigating between websites.

ZYVORA considers the following values strong:

```text
no-referrer
same-origin
strict-origin
strict-origin-when-cross-origin
```

### 6. Permissions-Policy

Controls access to browser features such as camera, microphone, and geolocation.

ZYVORA checks whether the header is present.

---

## Security Architecture

Because the application accepts a user-provided website URL and performs a server-side request, protecting against **Server-Side Request Forgery (SSRF)** is an important part of the design.

ZYVORA includes multiple protections around outbound requests.

### SSRF Protection

The scanner:

- Allows only HTTP and HTTPS URLs.
- Rejects URLs containing usernames or passwords.
- Restricts connections to standard ports.
- Rejects localhost targets.
- Resolves hostnames before connecting.
- Validates resolved IP addresses.
- Rejects private IP addresses.
- Rejects loopback addresses.
- Rejects link-local addresses.
- Rejects reserved addresses.
- Rejects multicast and unspecified addresses.
- Blocks cloud metadata/link-local destinations.
- Revalidates redirect destinations.
- Limits the number of redirects.
- Tries only validated public IP addresses.

### Request Protection

The application also:

- Limits URL length.
- Limits incoming request size.
- Uses connection and read timeouts.
- Uses an overall scan deadline.
- Does not download the target response body.
- Reads only the response headers required for analysis.
- Limits displayed response-header values.
- Redacts sensitive response headers.

Sensitive headers such as the following are not displayed in the raw-header section:

```text
Set-Cookie
Authorization
Proxy-Authorization
Cookie
```

---

## Application Security Headers

ZYVORA also protects its own responses with security headers.

The application adds protections including:

```text
Content-Security-Policy
Strict-Transport-Security
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy
Cross-Origin-Opener-Policy
Cross-Origin-Resource-Policy
X-DNS-Prefetch-Control
Cache-Control
```

This means the analyzer is itself configured with browser security protections.

---

## Technology Stack

### Backend

- Python
- Flask
- urllib3

### Frontend

- HTML5
- CSS3
- Jinja2 templates
- SVG icons

### Deployment

- GitHub
- Vercel

---

## Project Structure

```text
zyvora-security-header-analyzer/
│
├── app.py
├── analyzer.py
├── requirements.txt
├── vercel.json
├── README.md
│
├── templates/
│   └── index.html
│
└── static/
    └── style.css
```

### File Description

| File | Purpose |
|---|---|
| `app.py` | Flask application, URL validation, secure fetching, routing, and security controls |
| `analyzer.py` | Security-header analysis and scoring logic |
| `templates/index.html` | Main web interface and security report |
| `static/style.css` | UI styling and responsive design |
| `requirements.txt` | Python dependencies |
| `vercel.json` | Vercel deployment configuration |
| `README.md` | Project documentation |

---

## Installation

### Requirements

- Python 3.x
- pip
- Internet connection

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/zyvora-security-header-analyzer.git
cd zyvora-security-header-analyzer
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

The application will normally be available at:

```text
http://127.0.0.1:5000
```

---

## Deployment

ZYVORA can be deployed on Vercel using the included `vercel.json` configuration.

Basic deployment workflow:

```text
GitHub Repository
       ↓
     Vercel
       ↓
   Flask App
       ↓
Public Web Application
```

After deployment, Vercel provides a public URL that can be accessed from the internet.

---

## How to Use

1. Open the ZYVORA web application.
2. Enter a website address.
3. Click **ANALYZE**.
4. ZYVORA retrieves the target's HTTP response headers.
5. The six security headers are evaluated.
6. A score and grade are generated.
7. Review the security report.
8. Follow the recommended fixes where necessary.
9. Re-scan the website after making changes.

Example:

```text
https://example.com
```

---

## Example Result

A website with all six required protections passing can receive:

```text
6 / 6 PASSED

100 / 100

Grade: S
Exceptional
```

A website with missing security headers will receive a lower score and recommendations for improvement.

---

## Security Design Considerations

ZYVORA is designed as a security-header inspection tool, not as a complete website vulnerability scanner.

A high score means that the checked security headers passed the tool's validation rules.

It does **not** mean that:

- The website contains no vulnerabilities.
- The application has no security bugs.
- The server is completely secure.
- Authentication is secure.
- The database is secure.
- The website is free from malware.
- The application has passed a complete penetration test.

The analysis is specifically focused on the six security headers implemented by this project.

---

## Limitations

Some websites may not respond to server-side requests from cloud infrastructure.

Large websites and services using CDNs, bot protection, geographic filtering, or restrictive firewalls may:

- Delay the connection.
- Reject the request.
- Return different headers.
- Block cloud/serverless IP addresses.

Therefore, a timeout does not necessarily mean that the target website is down.

---

## Security Disclaimer

ZYVORA is intended for educational, research, and authorized security-testing purposes.

Only analyze websites that you are authorized to inspect.

Do not use the application to bypass access controls, attack systems, or perform unauthorized security testing.

---

## Project Objective

The primary objective of this project is to develop a simple and understandable tool for inspecting HTTP security headers and communicating their security importance to users.

The project combines:

- Web development
- HTTP response analysis
- Security-header validation
- Security scoring
- SSRF protection
- Secure server-side networking
- Cloud deployment

---

## Future Improvements

Possible future enhancements include:

- More HTTP security-header checks
- Historical scan reports
- PDF report generation
- Security-header comparison between scans
- Additional security recommendations
- API-based scanning
- Authentication for private reports
- More advanced CSP analysis
- Additional deployment monitoring

---

## References

### OWASP

Content Security Policy Cheat Sheet:

https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

HTTP Strict Transport Security Cheat Sheet:

https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html

HTTP Headers Cheat Sheet:

https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

Clickjacking Defense Cheat Sheet:

https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

### MDN Web Docs

Content Security Policy:

https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP

Strict-Transport-Security:

https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security

X-Content-Type-Options:

https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options

X-Frame-Options:

https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options

Referrer-Policy:

https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Referrer_policy

Permissions-Policy:

https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Permissions_Policy

---

## Author

**Minor Project — Security Header Analyzer**

**Project Name:** ZYVORA  
**Product:** Website Security Inspector

> **Security Made Clear**
