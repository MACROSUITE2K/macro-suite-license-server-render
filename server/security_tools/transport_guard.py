from __future__ import annotations

from typing import Any

from fastapi import Request


LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _host_without_port(host_header: str | None) -> str:
    if not host_header:
        return ""

    host = host_header.strip().lower()
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host


def _is_local_request(request: Request) -> bool:
    host = _host_without_port(request.headers.get("host"))
    if host not in LOCAL_HOSTS:
        return False

    if request.client is None:
        return True

    return request.client.host in LOCAL_HOSTS


def request_uses_https(request: Request, settings: Any) -> bool:
    forwarded_header = str(getattr(settings, "proxy_proto_header", "x-forwarded-proto")).strip().lower()
    forwarded_value = request.headers.get(forwarded_header)
    if forwarded_value:
        proto = forwarded_value.split(",", 1)[0].strip().lower()
        if proto == "https":
            return True

    return request.url.scheme.lower() == "https"


def require_https_or_localhost(request: Request, settings: Any) -> None:
    if not bool(getattr(settings, "require_https", True)):
        return

    if request_uses_https(request, settings):
        return

    if bool(getattr(settings, "allow_http_localhost", False)) and _is_local_request(request):
        return

    raise PermissionError("HTTPS is required. Refusing insecure HTTP request.")
