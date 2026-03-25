"""
Read .env files in the target project directory and merge them with
os.environ.  Supports .env, .env.local, .env.development, .env.production.
"""

import os
from pathlib import Path

_ENV_FILES = [".env", ".env.local", ".env.development", ".env.production"]


def read_env(project_dir: str) -> dict:
    """Return a merged dict of environment variables from .env files + os.environ."""
    merged: dict = {}

    for filename in _ENV_FILES:
        path = Path(project_dir) / filename
        if not path.exists():
            continue
        try:
            parsed = _parse_dotenv(path.read_text(encoding="utf-8"))
            merged.update(parsed)
        except OSError:
            pass

    # Fill in any os.environ variables not already set by .env files.
    # .env files take precedence over os.environ to allow local dev overrides.
    for key, value in os.environ.items():
        if key not in merged:
            merged[key] = value

    return merged


def _parse_dotenv(content: str) -> dict:
    result: dict = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        eq_idx = line.find("=")
        if eq_idx < 1:
            continue
        key = line[:eq_idx].strip()
        value = line[eq_idx + 1:].strip()
        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        result[key] = value
    return result
