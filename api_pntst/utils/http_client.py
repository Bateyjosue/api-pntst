"""Lightweight HTTP client wrapper (requests-based)."""

import urllib3
import requests

# Suppress InsecureRequestWarning when verify=False is used deliberately
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_DEFAULT_UA = "api-pntst/1.0 (github.com/Bateyjosue/api-pntst)"


def _base_kwargs(timeout: int, headers: dict, verify_ssl: bool = True) -> dict:
    return {
        "timeout": timeout,
        "headers": {"User-Agent": _DEFAULT_UA, **headers},
        "allow_redirects": True,
        "verify": verify_ssl,
    }


def http_get(url: str, timeout: int = 8, headers: dict | None = None, verify_ssl: bool = True):
    """GET request; never raises on HTTP error status."""
    try:
        return requests.get(url, **_base_kwargs(timeout, headers or {}, verify_ssl))
    except requests.RequestException:
        return None


def http_request(
    method: str,
    url: str,
    timeout: int = 8,
    headers: dict | None = None,
    params: dict | None = None,
    json_data=None,
    data=None,
    verify_ssl: bool = True,
):
    """Generic HTTP request; returns None on network failure."""
    kwargs = _base_kwargs(timeout, headers or {}, verify_ssl)
    if params:
        kwargs["params"] = params
    if json_data is not None:
        kwargs["json"] = json_data
    if data is not None:
        kwargs["data"] = data
    try:
        return requests.request(method.upper(), url, **kwargs)
    except requests.RequestException:
        return None
