"""SQL Injection Scanner — tests endpoints with common payloads and detects DB errors."""

import re
from api_pntst.utils.http_client import http_request

_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "1 UNION SELECT 1,2,3--",
    "admin'--",
    "' AND SLEEP(0)--",
    "1' ORDER BY 100--",
    "' AND 1=CONVERT(int,@@version)--",
    "1; EXEC xp_cmdshell('dir')--",
]

_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d{5}|pg_query|SQLiteException"
    r"|Microsoft OLE DB|Unclosed quotation mark|syntax error.*near"
    r"|unterminated quoted string|SQLSTATE|warning.*mysql"
    r"|You have an error in your SQL syntax|Column count doesn't match"
    r"|supplied argument is not a valid MySQL)",
    re.IGNORECASE | re.DOTALL,
)


def sql_injection_scanner(context: dict) -> list[dict]:
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
            if isinstance(p, dict) and p.get("in") in ("query", "path", "formData")
        ]
        targets = param_names or ["id", "search", "q", "query", "user", "username", "name"]
        verify_ssl = context.get("verify_ssl", True)

        for payload in _PAYLOADS:
            resp = None
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
            except Exception:
                continue

            if resp is None:
                continue

            body = resp.text or ""
            if _ERROR_PATTERNS.search(body):
                findings.append({
                    "scanner": "SQL Injection",
                    "severity": "critical",
                    "endpoint": f"{method} {url}",
                    "title": "SQL Injection Vulnerability Detected",
                    "description": (
                        f"The endpoint returned a database error message when injected with: {payload}"
                    ),
                    "evidence": body[:300],
                    "payload": payload,
                    "status_code": resp.status_code,
                    "remediation": (
                        "Use parameterised queries / prepared statements. Never concatenate user "
                        "input into SQL queries. Consider using an ORM with built-in protections."
                    ),
                    "references": [
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                })
                break  # One finding per endpoint is enough

            # 500 error on injection attempt — possible unhandled error
            if resp.status_code >= 500:
                findings.append({
                    "scanner": "SQL Injection",
                    "severity": "medium",
                    "endpoint": f"{method} {url}",
                    "title": "Server Error on SQL Injection Attempt",
                    "description": (
                        f"Server returned HTTP {resp.status_code} for payload: {payload}. "
                        "This may indicate an unhandled SQL injection vulnerability."
                    ),
                    "evidence": body[:200],
                    "payload": payload,
                    "status_code": resp.status_code,
                    "remediation": "Investigate and ensure all database queries are parameterised.",
                    "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                })
                break

    return findings
