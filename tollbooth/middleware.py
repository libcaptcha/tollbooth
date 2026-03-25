import http.cookies
import json
import types
from typing import Any, Unpack
from urllib.parse import parse_qs

from .engine import VERIFY_PATH, Request
from .integrations.base import Response, TollboothBase, TollboothKwargs

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


def _remote_addr(forwarded: str, fallback: str) -> str:
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
            form = _parse_form(
                environ["wsgi.input"].read(length),
            )
        except (ValueError, KeyError):
            pass

    return {
        "method": str(
            environ.get("REQUEST_METHOD", "GET"),
        ),
        "path": str(environ.get("PATH_INFO", "/")),
        "query": str(environ.get("QUERY_STRING", "")),
        "user_agent": str(
            environ.get("HTTP_USER_AGENT", ""),
        ),
        "remote_addr": _remote_addr(
            str(
                environ.get("HTTP_X_FORWARDED_FOR", ""),
            ),
            str(environ.get("REMOTE_ADDR", "")),
        ),
        "headers": headers,
        "cookies": parse_cookies(
            str(environ.get("HTTP_COOKIE", "")),
        ),
        "form": form,
    }


def _parse_scope(scope: dict[str, Any]) -> Request:
    raw = scope.get("headers", [])
    headers = {k.decode(): v.decode() for k, v in raw}
    client = scope.get("client")
    return {
        "method": scope.get("method", "GET"),
        "path": scope.get("path", "/"),
        "query": (scope.get("query_string", b"").decode()),
        "user_agent": headers.get("user-agent", ""),
        "remote_addr": _remote_addr(
            headers.get("x-forwarded-for", ""),
            client[0] if client else "",
        ),
        "headers": headers,
        "cookies": parse_cookies(
            headers.get("cookie", ""),
        ),
        "form": {},
    }


async def _read_body(receive) -> bytes:
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if len(body) > 1_048_576 or not msg.get("more_body", False):
            break
    return body[:1_048_576]


async def _asgi_respond(send, result: Response):
    await send(
        {
            "type": "http.response.start",
            "status": result.status,
            "headers": [[k.encode(), v.encode()] for k, v in result.headers.items()],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": (result.body.encode() if result.body else b""),
        }
    )


class TollboothWSGI:
    def __init__(self, app, secret, **kwargs: Unpack[TollboothKwargs]):
        self.app = app
        self._tb = TollboothBase(
            secret=secret,
            **kwargs,
        )

    @property
    def engine(self):
        return self._tb.engine

    def __call__(self, environ, start_response):
        handler = self._tb.engine.policy.challenge_handler
        if (
            environ.get("REQUEST_METHOD") == "POST"
            and environ.get("PATH_INFO") == self._tb.engine.policy.verify_path
            and "application/json" in environ.get("CONTENT_TYPE", "")
            and handler.supports_http_poll
        ):
            try:
                length = min(int(environ.get("CONTENT_LENGTH") or 0), 1_048_576)
                body = json.loads(environ["wsgi.input"].read(length))
                data = handler.handle_http_poll(body, self._tb.engine)
                start_response(
                    "200 OK",
                    [
                        ("Content-Type", "application/json"),
                        ("Cache-Control", "no-store"),
                    ],
                )
                return [json.dumps(data).encode()]
            except Exception:
                start_response(
                    "400 Bad Request", [("Content-Type", "application/json")]
                )
                return [b'{"error":"bad_request"}']

        request = parse_wsgi_request(environ)
        result = self._tb.process_request(request)

        if not result:
            environ["tollbooth.claims"] = request.get("_claims")
            return list(
                self.app(environ, start_response),
            )

        start_response(
            _status_line(result.status),
            list(result.headers.items()),
        )
        return [result.body.encode() if result.body else b""]


class TollboothASGI:
    def __init__(self, app, secret, **kwargs: Unpack[TollboothKwargs]):
        self.app = app
        self._tb = TollboothBase(
            secret=secret,
            **kwargs,
        )

    @property
    def engine(self):
        return self._tb.engine

    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket":
            handler = self._tb.engine.policy.challenge_handler
            if (
                handler.supports_websocket
                and scope.get("path") == self._tb.engine.policy.verify_path
            ):
                await handler.handle_websocket(scope, receive, send, self._tb.engine)
                return
            await self.app(scope, receive, send)
            return

        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = _parse_scope(scope)

        if self._tb.is_verify(request["method"], request["path"]):
            body_bytes = await _read_body(receive)
            ct = request["headers"].get("content-type", "")
            handler = self._tb.engine.policy.challenge_handler
            if "application/json" in ct and handler.supports_http_poll:
                try:
                    data = handler.handle_http_poll(
                        json.loads(body_bytes), self._tb.engine
                    )
                    await _asgi_respond(
                        send,
                        Response(
                            200,
                            {
                                "Content-Type": "application/json",
                                "Cache-Control": "no-store",
                            },
                            json.dumps(data),
                        ),
                    )
                except Exception:
                    await _asgi_respond(
                        send,
                        Response(
                            400,
                            {"Content-Type": "application/json"},
                            '{"error":"bad_request"}',
                        ),
                    )
                return
            request["form"] = _parse_form(body_bytes)

        result = self._tb.process_request(request)

        if not result:
            claims = request.get("_claims")
            if claims:
                state = scope.get("state")
                if state is None:
                    scope["state"] = types.SimpleNamespace(tollbooth=claims)
                else:
                    state.tollbooth = claims
            await self.app(scope, receive, send)
            return

        await _asgi_respond(send, result)
