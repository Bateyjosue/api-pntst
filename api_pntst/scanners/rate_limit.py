"""Rate Limiting Scanner — detects missing rate limiting via burst requests."""

import threading
from api_pntst.utils.http_client import http_request

_BURST_SIZE = 20
_AUTH_PATTERN = {"login", "auth", "token", "register", "signup", "forgot", "reset", "password"}


def rate_limit_scanner(context: dict) -> list[dict]:
    findings: list[dict] = []

    base_url = context["base_url"]
    endpoints = context["endpoints"]
    timeout = min(context["timeout"], 5)
    extra_headers = context["extra_headers"]

    # Prioritise auth-related endpoints
    priority = [e for e in endpoints if any(k in e["path"].lower() for k in _AUTH_PATTERN)]
    test_targets = [{"method": "GET", "url": base_url}] + priority[:3]
    verify_ssl = context.get("verify_ssl", True)

    for target in test_targets:
        url = target["url"]
        method = target.get("method", "GET")

        if not _is_rate_limited(method, url, timeout, extra_headers, verify_ssl):
            is_auth = any(k in url.lower() for k in _AUTH_PATTERN)
            findings.append({
                "scanner": "Rate Limiting",
                "severity": "high" if is_auth else "medium",
                "endpoint": f"{method} {url}",
                "title": (
                    "No Rate Limiting on Authentication Endpoint"
                    if is_auth
                    else "No Rate Limiting Detected"
                ),
                "description": (
                    f"The authentication endpoint did not throttle {_BURST_SIZE} rapid requests. "
                    "This enables brute-force and credential stuffing attacks."
                    if is_auth
                    else f"No HTTP 429 was returned after {_BURST_SIZE} rapid requests. "
                    "The API may be vulnerable to DoS or brute-force attacks."
                ),
                "evidence": f"{_BURST_SIZE} requests sent with no HTTP 429 received",
                "payload": None,
                "status_code": None,
                "remediation": (
                    "Implement rate limiting (e.g., 5 attempts/min/IP) with account lockout and CAPTCHA."
                    if is_auth
                    else "Implement API-level rate limiting (e.g., Flask-Limiter, slowapi, nginx limit_req). "
                    "Return HTTP 429 with a Retry-After header."
                ),
                "references": [
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
                ],
            })

    return findings


def _is_rate_limited(method: str, url: str, timeout: int, headers: dict, verify_ssl: bool = True) -> bool:
    """Send _BURST_SIZE concurrent requests; return True if any HTTP 429 is received."""
    rate_limited = threading.Event()

    def _request():
        try:
            resp = http_request(method, url, timeout=timeout, headers=headers, verify_ssl=verify_ssl)
            if resp and resp.status_code == 429:
                rate_limited.set()
        except Exception:
            pass  # Silently ignore individual thread failures

    threads = [threading.Thread(target=_request) for _ in range(_BURST_SIZE)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return rate_limited.is_set()
