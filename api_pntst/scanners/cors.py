"""CORS Misconfiguration Scanner — detects overly permissive cross-origin policies."""

from api_pntst.utils.http_client import http_request

_MALICIOUS_ORIGINS = ["https://evil.com", "https://attacker.com", "null"]


def cors_scanner(context: dict) -> list[dict]:
    findings: list[dict] = []
    seen: set[str] = set()

    # Test root + first few endpoints
    test_targets = [{"method": "GET", "url": context["base_url"]}]
    test_targets += context["endpoints"][:4]

    for target in test_targets:
        url = target["url"]
        method = target.get("method", "GET")
        verify_ssl = context.get("verify_ssl", True)

        for origin in _MALICIOUS_ORIGINS:
            try:
                resp = http_request(
                    method, url,
                    timeout=context["timeout"],
                    headers={"Origin": origin, **context["extra_headers"]},
                    verify_ssl=verify_ssl,
                )
                if resp is None:
                    continue

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if not acao:
                    continue

                finding_key = f"{url}:{acao}"
                if finding_key in seen:
                    continue

                if acao == "*":
                    seen.add(finding_key)
                    findings.append(_wildcard_finding(method, url, resp.status_code))

                elif acao == origin:
                    severity = "critical" if acac.lower() == "true" else "high"
                    seen.add(finding_key)
                    findings.append(_reflected_origin_finding(method, url, origin, acao, acac, severity, resp.status_code))

                elif origin == "null" and acao == "null":
                    seen.add(finding_key)
                    findings.append(_null_origin_finding(method, url, resp.status_code))

            except Exception:
                continue

    return findings


def _wildcard_finding(method, url, status_code):
    return {
        "scanner": "CORS",
        "severity": "medium",
        "endpoint": f"{method} {url}",
        "title": "Wildcard CORS Policy (Access-Control-Allow-Origin: *)",
        "description": (
            "The API responds with Access-Control-Allow-Origin: * allowing any origin. "
            "Acceptable for public APIs but dangerous if combined with credentials or sensitive data."
        ),
        "evidence": "Access-Control-Allow-Origin: *",
        "payload": "Origin: https://evil.com",
        "status_code": status_code,
        "remediation": (
            "Whitelist specific trusted origins. Never combine wildcard CORS with Allow-Credentials: true."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            "https://portswigger.net/web-security/cors",
        ],
    }


def _reflected_origin_finding(method, url, origin, acao, acac, severity, status_code):
    return {
        "scanner": "CORS",
        "severity": severity,
        "endpoint": f"{method} {url}",
        "title": (
            "CORS: Arbitrary Origin Accepted with Credentials"
            if severity == "critical"
            else "CORS: Arbitrary Origin Accepted"
        ),
        "description": (
            "The server reflects the attacker-controlled Origin header AND allows credentials. "
            "Full cross-origin authenticated requests are possible."
            if severity == "critical"
            else "The server reflects any attacker-controlled Origin, enabling cross-origin data theft."
        ),
        "evidence": (
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Access-Control-Allow-Credentials: {acac or '(not set)'}"
        ),
        "payload": f"Origin: {origin}",
        "status_code": status_code,
        "remediation": (
            "Maintain an explicit allowlist of trusted origins. "
            "Never reflect the Origin header dynamically without validation. "
            "Never allow credentials alongside a wildcard or reflected origin."
        ),
        "references": [
            "https://portswigger.net/web-security/cors",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
        ],
    }


def _null_origin_finding(method, url, status_code):
    return {
        "scanner": "CORS",
        "severity": "high",
        "endpoint": f"{method} {url}",
        "title": "CORS: Null Origin Accepted",
        "description": (
            "The server accepts 'null' as a valid origin. "
            "Sandboxed iframes and local file requests carry a null origin and may be abused."
        ),
        "evidence": "Access-Control-Allow-Origin: null",
        "payload": "Origin: null",
        "status_code": status_code,
        "remediation": "Do not whitelist the null origin. Use an explicit allowlist.",
        "references": ["https://portswigger.net/web-security/cors"],
    }
