# api-pntst — API Penetration Testing Tool

A Python CLI tool that **auto-discovers API routes and Swagger documentation**, runs **OWASP Top-10 security checks**, and produces a **rich HTML report** with detailed findings and remediation guidance.

---

## Features

| Category | Checks |
|---|---|
| 🛡 Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cache-Control, Server fingerprinting |
| 🌐 CORS | Wildcard policy, reflected arbitrary origin, null-origin acceptance, credentials with wildcard |
| 🔐 Authentication | Unauthenticated access, invalid JWT acceptance, JWT "alg:none" bypass |
| 💉 SQL Injection | Common payloads, DB error detection, 500-error on injection |
| ⚡ XSS | Reflected payload detection in HTML and JSON responses |
| 🔍 Sensitive Data | Passwords, private keys, AWS keys, JWTs, credit cards, SSNs, connection strings |
| 🔧 HTTP Methods | TRACE enabled, dangerous methods in Allow header, unauthenticated PUT/DELETE |
| ⏱ Rate Limiting | Burst testing on all endpoints (especially authentication routes) |

**Route Discovery:**
- Swagger/OpenAPI layered discovery (direct URL, well-known paths, Swagger UI parsing, local spec fallback)
- Source code scanning: Flask, FastAPI, Django (Python) · Express, Fastify, NestJS, Koa (JS/TS)
- `.env` file reading for `BASE_URL`, `PORT`, auth tokens, and more

---

## Installation

```bash
pip install api-pntst
```

Or install from source:

```bash
git clone https://github.com/Bateyjosue/api-pntst
cd api-pntst
pip install -e .
```

---

## Quick Start

```bash
# Auto-detect URL from your project's .env file
cd /path/to/your/project
api-pntst

# Specify the target URL explicitly
api-pntst --url http://localhost:3000

# Interactive setup (choose options step-by-step)
api-pntst --interactive

# Use a direct Swagger/OpenAPI URL
api-pntst --url https://api.example.com --swagger-url https://api.example.com/v3/api-docs

# Scan with a custom auth header and save the report
api-pntst --url https://api.example.com \
          --header "Authorization: Bearer <your-token>" \
          --output security-report.html

# Only show high and above in terminal (HTML always shows everything)
api-pntst --url http://localhost:8000 --severity high
```

---

## Options

| Flag | Default | Description |
|---|---|---|
| `-u / --url` | auto | Base URL of the target API |
| `--swagger-url` | — | Direct URL to OpenAPI/Swagger spec (`json`/`yaml`) |
| `-d / --dir` | `.` (cwd) | Project directory to scan for routes and .env |
| `-o / --output` | `api-pntst-report.html` | HTML report output path |
| `-t / --timeout` | `8` | HTTP request timeout in seconds |
| `-H / --header` | — | Extra request header in `"Key: Value"` format (repeatable) |
| `--severity` | `info` | Minimum severity level for terminal output |
| `--no-html` | — | Skip HTML report generation |
| `--concurrency` | `5` | Concurrent scan threads |
| `--discovery-mode` | `hybrid` | Endpoint source: `hybrid`, `swagger`, or `code` |
| `--interactive` | — | Interactive prompt to configure a scan |

---

## URL Auto-Detection

When `--url` is not provided, `api-pntst` searches for the target URL in these `.env` keys (in order):

1. `BASE_URL`, `API_URL`, `APP_URL`, `SERVER_URL`, `BACKEND_URL`
2. `PORT` + `HOST` → constructs `http://HOST:PORT`

Auth tokens are also picked up automatically from `AUTH_TOKEN`, `API_TOKEN`, `ACCESS_TOKEN`, `BEARER_TOKEN`, `API_KEY`, or `X_API_KEY`.

## Swagger/OpenAPI Discovery Strategy

`api-pntst` now uses a layered approach for better coverage on deployed and local targets:

1. Use `--swagger-url` if provided (best accuracy)
2. Probe well-known OpenAPI paths on the target base URL
3. Parse Swagger UI HTML and extract configured spec URLs
4. Fall back to local OpenAPI files in `--dir` (for local source scans)
5. If no spec is found, fall back to source route discovery (hybrid/code mode) and active endpoint probing

For production/deployed scans, prefer:

```bash
api-pntst --url https://api.example.com --swagger-url https://api.example.com/v3/api-docs --discovery-mode hybrid
```

For local development scans, prefer:

```bash
api-pntst --url http://localhost:3000 --dir . --discovery-mode hybrid
```

---

## HTML Report

The generated report (`api-pntst-report.html`) is fully self-contained and includes:

- **Summary dashboard** — severity counts at a glance
- **Doughnut chart** — visual breakdown by severity (Chart.js)
- **Endpoint table** — all discovered API routes with source (Swagger vs. code)
- **Collapsible finding cards** — description, evidence, payload used, HTTP status, remediation steps, and OWASP references
- **Severity filter buttons** — filter findings by Critical / High / Medium / Low / Info
- **Dark theme** — easy on the eyes during long security reviews

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan complete — no critical or high findings |
| `1` | Critical or high severity findings detected (use for CI/CD gating) |

---

## Development

```bash
# Install in editable mode
pip install -e .

# Run tests
pip install pytest
pytest

# Run against a local API
api-pntst --url http://localhost:3000
```

---

## License

MIT © 2026 Josue Batey
