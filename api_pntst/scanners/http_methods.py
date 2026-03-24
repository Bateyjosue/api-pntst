"""HTTP Methods Scanner — detects dangerous or unexpected HTTP methods on endpoints."""

from api_pntst.utils.http_client import http_request

_DANGEROUS_METHODS = {"TRACE", "TRACK", "CONNECT", "DEBUG"}
_AUTH_KEYS = {"authorization", "x-auth-token", "x-api-key"}


def http_methods_scanner(context: dict) -> list[dict]:
    findings: list[dict] = []
    seen: set[str] = set()

    base_url = context["base_url"]
    endpoints = context["endpoints"]
    timeout = context["timeout"]
    extra_headers = context["extra_headers"]

    # Endpoints to probe for TRACE + OPTIONS (root + first 4)
    probe_urls = list({base_url, *(e["url"] for e in endpoints[:4])})
    verify_ssl = context.get("verify_ssl", True)

    for url in probe_urls:
        # ── TRACE ────────────────────────────────────────────────────────────
        resp = http_request("TRACE", url, timeout=timeout, headers=extra_headers, verify_ssl=verify_ssl)
        if resp and resp.status_code < 400:
            key = f"TRACE:{url}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "scanner": "HTTP Methods",
                    "severity": "medium",
                    "endpoint": f"TRACE {url}",
                    "title": "TRACE Method Enabled",
                    "description": (
                        "HTTP TRACE echoes request headers back. "
                        "Attackers can use it in Cross-Site Tracing (XST) to steal cookies/auth headers."
                    ),
                    "evidence": f"TRACE {url} → HTTP {resp.status_code}",
                    "payload": "Method: TRACE",
                    "status_code": resp.status_code,
                    "remediation": "Disable the TRACE HTTP method in your web server or framework configuration.",
                    "references": ["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                })

        # ── OPTIONS — check Allow header for dangerous methods ────────────────
        resp_opt = http_request("OPTIONS", url, timeout=timeout, headers=extra_headers, verify_ssl=verify_ssl)
        if resp_opt:
            allow = (
                resp_opt.headers.get("Allow", "")
                + resp_opt.headers.get("Access-Control-Allow-Methods", "")
            ).upper()
            dangerous = [m for m in _DANGEROUS_METHODS if m in allow]
            if dangerous:
                key = f"OPTIONS-DANGEROUS:{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "scanner": "HTTP Methods",
                        "severity": "medium",
                        "endpoint": f"OPTIONS {url}",
                        "title": f"Dangerous HTTP Methods Allowed: {', '.join(dangerous)}",
                        "description": f"The Allow header lists dangerous HTTP methods: {', '.join(dangerous)}.",
                        "evidence": f"Allow: {allow}",
                        "payload": "Method: OPTIONS",
                        "status_code": resp_opt.status_code,
                        "remediation": f"Disable these methods in your server configuration: {', '.join(dangerous)}",
                        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
                    })

    # ── PUT / DELETE without auth ────────────────────────────────────────────
    no_auth_headers = {k: v for k, v in extra_headers.items() if k.lower() not in _AUTH_KEYS}

    for endpoint in endpoints:
        url = endpoint["url"]
        for method in ("PUT", "DELETE"):
            resp = http_request(
                method, url, timeout=timeout,
                headers={"Content-Type": "application/json", **no_auth_headers},
                json_data={} if method == "PUT" else None,
                verify_ssl=verify_ssl,
            )
            if resp and 200 <= resp.status_code < 300:
                key = f"{method}-UNAUTH:{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "scanner": "HTTP Methods",
                        "severity": "high",
                        "endpoint": f"{method} {url}",
                        "title": f"{method} Accepted Without Authentication",
                        "description": (
                            f"The endpoint accepted an unauthenticated {method} request and returned success. "
                            "This may allow unauthorised data modification or deletion."
                        ),
                        "evidence": f"{method} {url} → HTTP {resp.status_code}",
                        "payload": f"Method: {method}, no auth headers",
                        "status_code": resp.status_code,
                        "remediation": (
                            "Require authentication and authorisation for all state-changing HTTP methods. "
                            "Implement proper access-control checks."
                        ),
                        "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                    })

    return findings
