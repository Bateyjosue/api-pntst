"""
Authentication Scanner — tests for auth bypass, missing enforcement,
and JWT misconfiguration (algorithm none, invalid token acceptance).
"""

import base64
import json
from api_pntst.utils.http_client import http_request

_AUTH_HEADER_KEYS = {"authorization", "x-auth-token", "x-api-key"}


def auth_scanner(context: dict) -> list[dict]:
    findings: list[dict] = []
    seen: set[str] = set()

    # Headers stripped of any auth values (to test unauthenticated access)
    no_auth_headers = {
        k: v for k, v in context["extra_headers"].items()
        if k.lower() not in _AUTH_HEADER_KEYS
    }

    for endpoint in context["endpoints"]:
        method = endpoint["method"]
        url = endpoint["url"]
        # If swagger says no security required, skip auth checks
        endpoint_security = endpoint.get("security")
        if isinstance(endpoint_security, list) and len(endpoint_security) == 0:
            continue

        verify_ssl = context.get("verify_ssl", True)

        # ── 1. No credentials at all ─────────────────────────────────────
        resp_no_auth = http_request(method, url, timeout=context["timeout"], headers=no_auth_headers, verify_ssl=verify_ssl)
        if resp_no_auth and 200 <= resp_no_auth.status_code < 300:
            if endpoint_security is not None:
                key = f"no-auth:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "scanner": "Authentication",
                        "severity": "critical",
                        "endpoint": f"{method} {url}",
                        "title": "Auth Bypass: Endpoint Accessible Without Credentials",
                        "description": (
                            "This endpoint is documented as requiring authentication "
                            "but returned HTTP 2xx without any auth credentials."
                        ),
                        "evidence": f"HTTP {resp_no_auth.status_code} with no Authorization header",
                        "payload": "No Authorization header",
                        "status_code": resp_no_auth.status_code,
                        "remediation": (
                            "Enforce authentication middleware on all protected routes. "
                            "Use a centralised auth guard rather than per-route checks."
                        ),
                        "references": [
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                        ],
                    })

        # ── 2. Invalid JWT ────────────────────────────────────────────────
        resp_bad_jwt = http_request(
            method, url, timeout=context["timeout"],
            headers={**no_auth_headers, "Authorization": "Bearer invalid.jwt.token"},
            verify_ssl=verify_ssl,
        )
        if resp_bad_jwt and 200 <= resp_bad_jwt.status_code < 300:
            key = f"bad-jwt:{method}:{url}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "scanner": "Authentication",
                    "severity": "critical",
                    "endpoint": f"{method} {url}",
                    "title": "Invalid JWT Token Accepted",
                    "description": (
                        "The endpoint accepted a malformed JWT (invalid.jwt.token) and returned HTTP 2xx. "
                        "JWT signature verification is not being performed."
                    ),
                    "evidence": f"HTTP {resp_bad_jwt.status_code} with invalid JWT",
                    "payload": "Authorization: Bearer invalid.jwt.token",
                    "status_code": resp_bad_jwt.status_code,
                    "remediation": (
                        "Verify JWT signatures (RS256 or HS256). "
                        "Validate exp, iss, and aud claims. Reject the 'none' algorithm."
                    ),
                    "references": [
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
                    ],
                })

        # ── 3. JWT "alg: none" bypass ─────────────────────────────────────
        none_jwt = _build_none_alg_jwt({"sub": "admin", "role": "admin"})
        resp_none = http_request(
            method, url, timeout=context["timeout"],
            headers={**no_auth_headers, "Authorization": f"Bearer {none_jwt}"},
            verify_ssl=verify_ssl,
        )
        if resp_none and 200 <= resp_none.status_code < 300:
            key = f"alg-none:{method}:{url}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "scanner": "Authentication",
                    "severity": "critical",
                    "endpoint": f"{method} {url}",
                    "title": 'JWT "Algorithm None" Bypass',
                    "description": (
                        'The endpoint accepted an unsigned JWT with alg set to "none". '
                        "Attackers can forge any identity without a secret key."
                    ),
                    "evidence": f"HTTP {resp_none.status_code} with alg:none JWT",
                    "payload": f"Authorization: Bearer {none_jwt}",
                    "status_code": resp_none.status_code,
                    "remediation": (
                        'Whitelist allowed JWT algorithms. Explicitly reject "none". '
                        "Use a maintained JWT library (PyJWT, python-jose)."
                    ),
                    "references": [
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        "https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature",
                    ],
                })

    return findings


def _build_none_alg_jwt(payload: dict) -> str:
    """Build an unsigned JWT with alg=none — for testing purposes only."""
    def _b64(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    header = _b64({"alg": "none", "typ": "JWT"})
    body = _b64(payload)
    return f"{header}.{body}."
