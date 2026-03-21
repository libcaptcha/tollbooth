import http.cookies
from typing import Any
from urllib.parse import parse_qs

from .engine import VERIFY_PATH, Engine, Request

__all__ = [
    "VERIFY_PATH",
    "TollboothWSGI",
    "TollboothASGI",
    "parse_cookies",
    "parse_wsgi_request",
]

STATUS_LINES = {
    302: "302 Found",
    403: "403 Forbidden",
    429: "429 Too Many Requests",
}


def parse_cookies(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    try:
        parsed = http.cookies.SimpleCookie(raw)
        return {k: v.value for k, v in parsed.items()}
    except http.cookies.CookieError:
        return {}


def _remote_addr(
    forwarded: str,
    fallback: str,
) -> str:
    if forwarded:
        return forwarded.split(",")[0].strip()
    return fallback


def _parse_form(body: bytes) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(body.decode()).items()}


def _status_line(code: int) -> str:
    return STATUS_LINES.get(code, f"{code} Error")


def parse_wsgi_request(
    environ: dict[str, Any],
) -> Request:
    headers = {
        key[5:].replace("_", "-").title(): str(value)
        for key, value in environ.items()
        if key.startswith("HTTP_")
    }

    form: dict[str, str] = {}
    if environ.get("REQUEST_METHOD") == "POST":
        try:
            length = min(
                int(environ.get("CONTENT_LENGTH", 0)),
                1_048_576,
            )
            form = _parse_form(environ["wsgi.input"].read(length))
        except (ValueError, KeyError):
            pass

    return {
        "method": str(environ.get("REQUEST_METHOD", "GET")),
        "path": str(environ.get("PATH_INFO", "/")),
        "query": str(environ.get("QUERY_STRING", "")),
        "user_agent": str(environ.get("HTTP_USER_AGENT", "")),
        "remote_addr": _remote_addr(
            str(environ.get("HTTP_X_FORWARDED_FOR", "")),
            str(environ.get("REMOTE_ADDR", "")),
        ),
        "headers": headers,
        "cookies": parse_cookies(str(environ.get("HTTP_COOKIE", ""))),
        "form": form,
    }


def _is_verify(request: Request, path: str) -> bool:
    return request["method"] == "POST" and request["path"] == path


class TollboothWSGI:
    def __init__(self, app, secret, **kwargs):
        self.app = app
        self.engine = Engine(secret=secret, **kwargs)

    def _respond(self, start_response, status, headers):
        start_response(
            _status_line(status),
            list(headers.items()),
        )

    def __call__(self, environ, start_response):
        request = parse_wsgi_request(environ)
        verify = self.engine.policy.verify_path

        if _is_verify(request, verify):
            status, headers, body = self.engine.handle_verify(request)
            self._respond(
                start_response,
                status,
                headers,
            )
            return [body.encode() if body else b""]

        action, status, headers, body = self.engine.process(request)

        if action == "pass":
            return list(self.app(environ, start_response))

        self._respond(start_response, status, headers)
        return [body.encode()]


async def _parse_asgi_request(
    scope: dict[str, Any],
    receive,
) -> Request:
    raw_headers = scope.get("headers", [])
    headers = {k.decode(): v.decode() for k, v in raw_headers}
    client = scope.get("client")

    form: dict[str, str] = {}
    if scope.get("method") == "POST":
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if len(body) > 1_048_576:
                break
            if not msg.get("more_body", False):
                break
        form = _parse_form(body[:1_048_576])

    return {
        "method": str(scope.get("method", "GET")),
        "path": str(scope.get("path", "/")),
        "query": (scope.get("query_string", b"").decode()),
        "user_agent": headers.get("user-agent", ""),
        "remote_addr": _remote_addr(
            headers.get("x-forwarded-for", ""),
            client[0] if client else "",
        ),
        "headers": headers,
        "cookies": parse_cookies(headers.get("cookie", "")),
        "form": form,
    }


async def _send_response(
    send,
    status,
    headers,
    body,
):
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [[k.encode(), v.encode()] for k, v in headers.items()],
        }
    )

    await send(
        {
            "type": "http.response.body",
            "body": body.encode() if body else b"",
        }
    )


class TollboothASGI:
    def __init__(self, app, secret, **kwargs):
        self.app = app
        self.engine = Engine(secret=secret, **kwargs)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = await _parse_asgi_request(
            scope,
            receive,
        )
        verify = self.engine.policy.verify_path

        if _is_verify(request, verify):
            status, headers, body = self.engine.handle_verify(request)
            await _send_response(
                send,
                status,
                headers,
                body,
            )
            return

        action, status, headers, body = self.engine.process(request)

        if action == "pass":
            await self.app(scope, receive, send)
            return

        await _send_response(
            send,
            status,
            headers,
            body,
        )
