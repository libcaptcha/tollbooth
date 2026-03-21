from ..middleware import _parse_form, parse_cookies
from .base import TollboothBase


def _parse_scope(scope):
    raw = scope.get("headers", [])
    headers = {k.decode(): v.decode() for k, v in raw}
    client = scope.get("client")
    forwarded = headers.get(
        "x-forwarded-for",
        "",
    )
    return {
        "method": scope.get("method", "GET"),
        "path": scope.get("path", "/"),
        "query": (scope.get("query_string", b"").decode()),
        "user_agent": headers.get(
            "user-agent",
            "",
        ),
        "remote_addr": (
            forwarded.split(",")[0].strip()
            if forwarded
            else (client[0] if client else "")
        ),
        "headers": headers,
        "cookies": parse_cookies(
            headers.get("cookie", ""),
        ),
        "form": {},
    }


async def _read_form(receive):
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if len(body) > 1_048_576:
            break
        if not msg.get("more_body", False):
            break
    return _parse_form(body[:1_048_576])


async def _send(send, result):
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


class TollboothMiddleware:
    def __init__(self, app, secret, **kwargs):
        self.app = app
        self._tb = TollboothBase(
            secret=secret,
            **kwargs,
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        request = _parse_scope(scope)

        if self._tb.is_verify(method, path):
            request["form"] = await _read_form(
                receive,
            )

        result = self._tb.process_request(request)
        if result:
            await _send(send, result)
            return

        await self.app(scope, receive, send)
