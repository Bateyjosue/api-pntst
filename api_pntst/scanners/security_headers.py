"""Security Headers Scanner — audits HTTP response headers for missing or weak settings."""

from api_pntst.utils.http_client import http_get

_REQUIRED_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "severity": "high",
        "description": (
            "Missing HSTS header. Browsers cannot enforce HTTPS, enabling downgrade attacks."
        ),
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Missing X-Content-Type-Options. Browsers may MIME-sniff responses, enabling XSS attacks.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    },
    {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Missing X-Frame-Options. The application may be vulnerable to clickjacking.",
        "remediation": "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    },
    {
        "name": "Content-Security-Policy",
        "severity": "high",
        "description": "Missing CSP header. No protection against XSS or data injection attacks.",
        "remediation": "Add: Content-Security-Policy: default-src 'self'",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
    },
    {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Missing Referrer-Policy. Sensitive URL parameters may leak to third parties.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    },
    {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Missing Permissions-Policy. Browser features (camera, mic, etc.) are unrestricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    },
]

_INFO_HEADERS = [
    {
        "name": "X-Powered-By",
        "severity": "info",
        "description": "X-Powered-By header discloses the server technology (fingerprinting).",
        "remediation": "Remove the X-Powered-By header.",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    {
        "name": "Server",
        "severity": "info",
        "description": "Server header discloses software and potentially version information.",
        "remediation": "Remove or minimise the Server header value.",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
]


def security_headers_scanner(context: dict) -> list[dict]:
    findings: list[dict] = []
    base_url = context["base_url"]

    verify_ssl = context.get("verify_ssl", True)
    resp = http_get(base_url, context["timeout"], context["extra_headers"], verify_ssl)
    if resp is None:
        return findings

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for hdr in _REQUIRED_HEADERS:
        if hdr["name"].lower() not in headers_lower:
            findings.append({
                "scanner": "Security Headers",
                "severity": hdr["severity"],
                "endpoint": f"GET {base_url}",
                "title": f"Missing Security Header: {hdr['name']}",
                "description": hdr["description"],
                "evidence": f'Header "{hdr["name"]}" was absent from the HTTP response.',
                "payload": None,
                "status_code": resp.status_code,
                "remediation": hdr["remediation"],
                "references": hdr["references"],
            })

    for hdr in _INFO_HEADERS:
        value = headers_lower.get(hdr["name"].lower())
        if value:
            findings.append({
                "scanner": "Security Headers",
                "severity": hdr["severity"],
                "endpoint": f"GET {base_url}",
                "title": f"Information Disclosure: {hdr['name']} Present",
                "description": hdr["description"],
                "evidence": f"{hdr['name']}: {value}",
                "payload": None,
                "status_code": resp.status_code,
                "remediation": hdr["remediation"],
                "references": hdr["references"],
            })

    # Cache-Control check
    cache_ctrl = headers_lower.get("cache-control", "")
    if "no-store" not in cache_ctrl and "no-cache" not in cache_ctrl:
        findings.append({
            "scanner": "Security Headers",
            "severity": "low",
            "endpoint": f"GET {base_url}",
            "title": "Insufficient Cache-Control Directives",
            "description": (
                "The response lacks 'no-store' or 'no-cache'. "
                "Sensitive responses may be cached by proxies or browsers."
            ),
            "evidence": f"Cache-Control: {cache_ctrl or '(not set)'}",
            "payload": None,
            "status_code": resp.status_code,
            "remediation": "Add: Cache-Control: no-store, no-cache, must-revalidate for sensitive endpoints.",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"],
        })

    return findings
