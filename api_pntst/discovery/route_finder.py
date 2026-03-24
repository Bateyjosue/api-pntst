"""
Static route discovery — scans Python and JavaScript/TypeScript source files
for route definitions from Flask, FastAPI, Django, Express, Fastify, NestJS, etc.

Returns a list of dicts: {"method": str, "path": str, "source": "code", "file": str}
"""

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Regex patterns grouped by language / framework
# ---------------------------------------------------------------------------
PYTHON_PATTERNS = [
    # Flask / Quart / Blueprint:  @app.route('/path', methods=['GET', 'POST'])
    (
        re.compile(
            r"""@\w+\.route\(\s*['"]([^'"]+)['"]\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?\s*\)""",
            re.IGNORECASE,
        ),
        "flask",
    ),
    # FastAPI / APIRouter decorators:  @router.get('/path'), @app.post('/path')
    (
        re.compile(
            r"""@\w+\.(get|post|put|patch|delete|head|options)\s*\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        ),
        "fastapi",
    ),
    # Django urls.py:  path('route/', view), re_path(r'^route/$', view)
    (
        re.compile(r"""(?:path|re_path|url)\s*\(\s*r?['"]([^'"]+)['"]""", re.IGNORECASE),
        "django",
    ),
]

JS_PATTERNS = [
    # Express / Koa / Fastify:  app.get('/path', ...), router.post('/path', ...)
    re.compile(
        r"""(?:app|router|server|fastify|api)\s*\.\s*(get|post|put|patch|delete|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    ),
    # NestJS decorators:  @Get('/path'), @Post('/path')
    re.compile(
        r"""@(Get|Post|Put|Patch|Delete|Options|Head)\s*\(\s*['"`]?([^'"`)\s]*)['"`]?\s*\)""",
        re.IGNORECASE,
    ),
]

_SKIP_DIRS = {
    "node_modules", "dist", "build", ".git", "__pycache__",
    ".venv", "venv", "env", ".eggs", "coverage", "htmlcov",
}
_TEMPLATE_CHARS = {"${", "#{", "{%", "{{"}


def find_routes(project_dir: str) -> list[dict]:
    root = Path(project_dir)
    if not root.exists():
        return []

    routes: list[dict] = []
    seen: set[str] = set()

    for path in _iter_source_files(root):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        suffix = path.suffix.lower()
        if suffix == ".py":
            _extract_python_routes(content, str(path), routes, seen)
        elif suffix in {".js", ".ts", ".mjs", ".cjs"}:
            _extract_js_routes(content, str(path), routes, seen)

    return routes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iter_source_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and not any(skip in p.parts for skip in _SKIP_DIRS):
            if p.suffix.lower() in {".py", ".js", ".ts", ".mjs", ".cjs"}:
                yield p


def _extract_python_routes(content: str, filepath: str, routes: list, seen: set):
    for pattern, framework in PYTHON_PATTERNS:
        for m in pattern.finditer(content):
            if framework == "fastapi":
                method = m.group(1).upper()
                raw_path = m.group(2)
            elif framework == "flask":
                raw_path = m.group(1)
                methods_str = m.group(2) or "GET"
                methods = [x.strip().strip("'\"").upper() for x in methods_str.split(",")]
                for method in methods:
                    _add_route(method, raw_path, filepath, "code", routes, seen)
                continue
            else:  # django — no method info
                raw_path = m.group(1).strip("^$").rstrip("/") or "/"
                method = "GET"

            _add_route(method, raw_path, filepath, "code", routes, seen)


def _extract_js_routes(content: str, filepath: str, routes: list, seen: set):
    for pattern in JS_PATTERNS:
        for m in pattern.finditer(content):
            method = m.group(1).upper()
            raw_path = m.group(2)
            _add_route(method, raw_path, filepath, "code", routes, seen)


def _add_route(method: str, raw_path: str, filepath: str, source: str, routes: list, seen: set):
    # Skip template-literal / dynamic base segments
    if any(c in raw_path for c in _TEMPLATE_CHARS):
        return
    if not raw_path:
        raw_path = "/"
    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path

    key = f"{method}:{raw_path}"
    if key in seen:
        return
    seen.add(key)
    routes.append({"method": method, "path": raw_path, "source": source, "file": filepath})
