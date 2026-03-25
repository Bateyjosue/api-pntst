"""XSS Scanner — checks whether injected payloads are reflected unescaped in responses."""

from api_pntst.utils.http_client import http_request

_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    'javascript:alert(1)',
    "<body onload=alert(1)>",
]


def xss_scanner(context: dict) -> list[dict]:
    findings: list[dict] = []

    for endpoint in context["endpoints"]:
        method = endpoint["method"]
        url = endpoint["url"]
        parameters = endpoint.get("parameters", [])

        if method not in ("GET", "POST", "PUT", "PATCH"):
            continue

        param_names = [
            p["name"]
            for p in parameters
            if isinstance(p, dict) and p.get("in") in ("query", "formData")
        ]
        targets = param_names or ["q", "search", "query", "name", "message", "content", "input"]
        verify_ssl = context.get("verify_ssl", True)

        for payload in _PAYLOADS:
            try:
                if method == "GET":
                    resp = http_request(
                        "GET", url,
                        timeout=context["timeout"],
                        headers=context["extra_headers"],
                        params={t: payload for t in targets},
                        verify_ssl=verify_ssl,
                    )
                else:
                    resp = http_request(
                        method, url,
                        timeout=context["timeout"],
                        headers={"Content-Type": "application/json", **context["extra_headers"]},
                        json_data={t: payload for t in targets},
                        verify_ssl=verify_ssl,
                    )

                if resp is None:
                    continue

                content_type = resp.headers.get("Content-Type", "").lower()
                body = resp.text or ""

                if payload in body:
                    is_html = "html" in content_type
                    findings.append({
                        "scanner": "XSS",
                        "severity": "high" if is_html else "medium",
                        "endpoint": f"{method} {url}",
                        "title": f"Reflected XSS Detected ({'HTML' if is_html else 'JSON'} context)",
                        "description": (
                            "The payload was reflected unescaped in the response. "
                            "An attacker may be able to inject malicious scripts into the page."
                        ),
                        "evidence": f"Payload: {payload}\nReflected in: {content_type}",
                        "payload": payload,
                        "status_code": resp.status_code,
                        "remediation": (
                            "HTML-encode all user-supplied output. Set a strict Content-Security-Policy. "
                            "Use templating engines that auto-escape by default."
                        ),
                        "references": [
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                    })
                    break  # One finding per endpoint

            except Exception:
                continue

    return findings
