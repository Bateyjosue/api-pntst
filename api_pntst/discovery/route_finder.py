"""
Static route discovery — scans Python, JavaScript/TypeScript, Go, and Java source
files for route definitions from Flask, FastAPI, Django, Express, Fastify, NestJS,
Gin, Echo, Fiber, Spring, JAX-RS, Ktor, etc.

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

GO_PATTERNS = [
    # Gin:       router.GET("/path", handler), r.POST("/path", handler)
    # Echo:      e.GET("/path", handler), g.POST("/path", handler)
    # Fiber:     app.Get("/path", handler), app.Post("/path", handler)
    # Gorilla Mux: r.HandleFunc("/path", handler).Methods("GET")
    re.compile(
        r"""(?:router|r|e|app|g|v\d)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Handle(?:Func)?)\s*\(\s*["'`]([^"'`]+)["'`]""",
        re.IGNORECASE,
    ),
    # Chi:  r.Get("/path", handler), r.Post("/path", handler)
    re.compile(
        r"""\b(Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*["'`]([^"'`]+)["'`]""",
        re.IGNORECASE,
    ),
    # net/http ServeMux:  http.HandleFunc("/path", handler), mux.Handle("/path", handler)
    re.compile(
        r"""(?:http\.HandleFunc|mux\.Handle(?:Func)?)\s*\(\s*["'`]([^"'`]+)["'`]""",
        re.IGNORECASE,
    ),
]

JAVA_PATTERNS = [
    # Spring MVC / Spring Boot:  @GetMapping("/path"), @RequestMapping(value="/path", method=...)
    (
        re.compile(
            r"""@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']""",
            re.IGNORECASE,
        ),
        "spring",
    ),
    # JAX-RS (Jersey, RESTEasy):  @GET / @POST / @PUT ... combined with @Path("/path")
    (
        re.compile(
            r"""@(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b[\s\S]{0,120}?@Path\s*\(\s*["']([^"']+)["']\s*\)""",
            re.IGNORECASE,
        ),
        "jaxrs",
    ),
    # JAX-RS @Path first, then method annotation (reverse order in source)
    (
        re.compile(
            r"""@Path\s*\(\s*["']([^"']+)["']\s*\)[\s\S]{0,120}?@(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b""",
            re.IGNORECASE,
        ),
        "jaxrs_rev",
    ),
    # Ktor routing DSL:  get("/path") { ... }, post("/path") { ... }
    (
        re.compile(
            r"""\b(get|post|put|patch|delete|head|options)\s*\(\s*["']([^"']+)["']\s*\)\s*\{""",
            re.IGNORECASE,
        ),
        "ktor",
    ),
]

_SPRING_METHOD_MAP = {
    "getmapping": "GET",
    "postmapping": "POST",
    "putmapping": "PUT",
    "patchmapping": "PATCH",
    "deletemapping": "DELETE",
    "requestmapping": "GET",  # default; actual method may vary
}

_SKIP_DIRS = {
    "node_modules", "dist", "build", ".git", "__pycache__",
    ".venv", "venv", "env", ".eggs", "coverage", "htmlcov",
    "target", "out", "bin", "obj", "vendor",
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
        elif suffix == ".go":
            _extract_go_routes(content, str(path), routes, seen)
        elif suffix in {".java", ".kt"}:
            _extract_java_routes(content, str(path), routes, seen)

    return routes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iter_source_files(root: Path):
    supported = {".py", ".js", ".ts", ".mjs", ".cjs", ".go", ".java", ".kt"}
    for p in root.rglob("*"):
        if p.is_file() and not any(skip in p.parts for skip in _SKIP_DIRS):
            if p.suffix.lower() in supported:
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


def _extract_go_routes(content: str, filepath: str, routes: list, seen: set):
    # Patterns that capture (method, path)
    for m in GO_PATTERNS[0].finditer(content):
        verb = m.group(1).upper()
        raw_path = m.group(2)
        # HandleFunc / Handle don't carry HTTP method info — default to GET
        if verb in {"HANDLE", "HANDLEFUNC"}:
            verb = "GET"
        _add_route(verb, raw_path, filepath, "code", routes, seen)

    for m in GO_PATTERNS[1].finditer(content):
        verb = m.group(1).upper()
        raw_path = m.group(2)
        _add_route(verb, raw_path, filepath, "code", routes, seen)

    # net/http HandleFunc — path only, no method
    for m in GO_PATTERNS[2].finditer(content):
        raw_path = m.group(1)
        _add_route("GET", raw_path, filepath, "code", routes, seen)


def _extract_java_routes(content: str, filepath: str, routes: list, seen: set):
    for pattern, framework in JAVA_PATTERNS:
        for m in pattern.finditer(content):
            if framework == "spring":
                annotation = m.group(1).lower()
                raw_path = m.group(2)
                method = _SPRING_METHOD_MAP.get(annotation, "GET")
            elif framework == "jaxrs":
                method = m.group(1).upper()
                raw_path = m.group(2)
            elif framework == "jaxrs_rev":
                raw_path = m.group(1)
                method = m.group(2).upper()
            else:  # ktor
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
