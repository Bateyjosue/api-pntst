"""Sensitive Data Exposure Scanner — searches API responses for leaked secrets and PII."""

import re
from api_pntst.utils.http_client import http_request

_PATTERNS = [
    {
        "name": "Password in Response",
        "regex": re.compile(r'"password"\s*:\s*"[^"]+"', re.IGNORECASE),
        "severity": "critical",
        "description": 'A field named "password" with a non-empty value was found in the response.',
    },
    {
        "name": "Private Key",
        "regex": re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
        "severity": "critical",
        "description": "A PEM-encoded private key was found in the response body.",
    },
    {
        "name": "AWS Access Key",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "critical",
        "description": "An AWS Access Key ID pattern was found in the response.",
    },
    {
        "name": "JWT Token",
        "regex": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*"),
        "severity": "high",
        "description": (
            "A JWT token was found in the response body. "
            "Tokens should not be stored or returned unnecessarily."
        ),
    },
    {
        "name": "Credit Card Number",
        "regex": re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
        ),
        "severity": "critical",
        "description": "A credit card number pattern was found in the response.",
    },
    {
        "name": "Social Security Number (SSN)",
        "regex": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "severity": "critical",
        "description": "A Social Security Number (SSN) pattern was found in the response.",
    },
    {
        "name": "Bulk Email Addresses",
        "regex": re.compile(
            r"(?:[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}.*?){5,}",
            re.DOTALL,
        ),
        "severity": "medium",
        "description": "5+ email addresses found in a single response — potential PII bulk exposure.",
    },
    {
        "name": "Secret / Token Field",
        "regex": re.compile(
            r'"(?:secret|api_key|apikey|access_token|auth_token|private_key|client_secret)"\s*:\s*"[^"]{8,}"',
            re.IGNORECASE,
        ),
        "severity": "critical",
        "description": "A field containing secret/token data with a non-empty value was found.",
    },
    {
        "name": "Database Connection String",
        "regex": re.compile(
            r"(?:mongodb|mysql|postgresql|postgres|redis|amqp):\/\/[^\s\"']+",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "description": "A database/service connection string was found in the response.",
    },
    {
        "name": "Internal IP Address",
        "regex": re.compile(
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "severity": "low",
        "description": "An internal IP address was found, indicating potential network topology disclosure.",
    },
]

_REDACT = re.compile(r"[a-zA-Z0-9+/=]{6,}")


def sensitive_data_scanner(context: dict) -> list[dict]:
    findings: list[dict] = []

    for endpoint in context["endpoints"]:
        if endpoint["method"] != "GET":
            continue

        url = endpoint["url"]
        verify_ssl = context.get("verify_ssl", True)
        resp = http_request("GET", url, timeout=context["timeout"], headers=context["extra_headers"], verify_ssl=verify_ssl)
        if resp is None or not (200 <= resp.status_code < 300):
            continue

        body = resp.text or ""

        for pattern in _PATTERNS:
            match = pattern["regex"].search(body)
            if match:
                masked = _REDACT.sub("***REDACTED***", match.group(0))
                findings.append({
                    "scanner": "Sensitive Data Exposure",
                    "severity": pattern["severity"],
                    "endpoint": f"GET {url}",
                    "title": f"Sensitive Data Exposure: {pattern['name']}",
                    "description": pattern["description"],
                    "evidence": masked,
                    "payload": None,
                    "status_code": resp.status_code,
                    "remediation": (
                        "Remove sensitive data from API responses. "
                        "Apply field-level filtering/masking. "
                        "Return only what the client genuinely needs (principle of least privilege)."
                    ),
                    "references": [
                        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
                    ],
                })

    return findings
