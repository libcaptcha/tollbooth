import io
from typing import Any

import pytest

from tollbooth.engine import (
    COOKIE_NAME,
    Engine,
    Policy,
    Request,
    Rule,
    _balloon,
    _count_leading_zero_bits,
)
from tollbooth.middleware import (
    VERIFY_PATH,
    TollboothASGI,
    TollboothWSGI,
    parse_cookies,
    parse_wsgi_request,
)

SECRET = "test-secret-key-32-bytes-long!!!"


def dummy_wsgi_app(
    _environ: dict[str, Any],
    start_response: Any,
) -> list[bytes]:
    start_response(
        "200 OK",
        [("Content-Type", "text/plain")],
    )
    return [b"upstream"]


async def dummy_asgi_app(
    scope: dict[str, Any],
    _receive: Any,
    send: Any,
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"text/plain"]],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": b"upstream",
        }
    )


def make_environ(
    method: str = "GET",
    path: str = "/",
    user_agent: str = "Mozilla/5.0",
    remote_addr: str = "1.2.3.4",
    cookie: str = "",
    body: bytes = b"",
) -> dict[str, Any]:
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "HTTP_USER_AGENT": user_agent,
        "REMOTE_ADDR": remote_addr,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "8000",
        "wsgi.input": io.BytesIO(body),
    }
    if cookie:
        environ["HTTP_COOKIE"] = cookie
    if body:
        environ["CONTENT_LENGTH"] = str(len(body))
        environ["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
    return environ


class CaptureResponse:
    status: str | None
    headers: dict[str, str]

    def __init__(self) -> None:
        self.status = None
        self.headers = {}

    def __call__(
        self,
        status: str,
        headers: list[tuple[str, str]],
    ) -> None:
        self.status = status
        self.headers = dict(headers)


def challenge_policy() -> Policy:
    return Policy(
        rules=[
            Rule(
                name="all",
                action="challenge",
                difficulty=1,
            ),
        ]
    )


def solve_for_engine(
    engine: Engine,
    remote_addr: str = "1.2.3.4",
) -> tuple[str, str]:
    request: Request = {
        "method": "GET",
        "remote_addr": remote_addr,
        "headers": {},
        "cookies": {},
        "user_agent": "",
        "path": "/",
        "query": "",
        "form": {},
    }
    challenge = engine.issue_challenge(1, request)
    policy = engine.policy

    for nonce in range(200_000):
        result = _balloon(
            challenge.random_data,
            nonce,
            policy.space_cost,
            policy.time_cost,
            policy.delta,
        )
        if _count_leading_zero_bits(result) >= 1:
            return challenge.id, str(nonce)

    raise RuntimeError("unsolvable")


class TestParseCookies:
    def test_empty(self) -> None:
        assert parse_cookies("") == {}

    def test_single(self) -> None:
        result = parse_cookies("name=value")
        assert result == {"name": "value"}

    def test_multiple(self) -> None:
        result = parse_cookies("a=1; b=2; c=3")
        assert result == {"a": "1", "b": "2", "c": "3"}

    def test_malformed(self) -> None:
        result = parse_cookies("invalid cookie!!!")
        assert isinstance(result, dict)


class TestParseWSGIRequest:
    def test_basic(self) -> None:
        environ = make_environ(
            path="/test",
            user_agent="Bot/1.0",
        )
        req = parse_wsgi_request(environ)
        assert req["path"] == "/test"
        assert req["user_agent"] == "Bot/1.0"
        assert req["remote_addr"] == "1.2.3.4"
        assert req["method"] == "GET"

    def test_x_forwarded_for(self) -> None:
        environ = make_environ()
        environ["HTTP_X_FORWARDED_FOR"] = "9.8.7.6, 5.4.3.2"
        req = parse_wsgi_request(environ)
        assert req["remote_addr"] == "9.8.7.6"

    def test_post_form(self) -> None:
        body = b"key=value&other=data"
        environ = make_environ(method="POST", body=body)
        req = parse_wsgi_request(environ)
        assert req["form"]["key"] == "value"
        assert req["form"]["other"] == "data"

    def test_cookies(self) -> None:
        environ = make_environ(cookie="a=1; b=2")
        req = parse_wsgi_request(environ)
        assert req["cookies"] == {"a": "1", "b": "2"}


class TestWSGIMiddleware:
    def test_pass_normal_request(self) -> None:
        mw = TollboothWSGI(
            dummy_wsgi_app,
            secret=SECRET,
            policy=Policy(rules=[]),
        )
        resp = CaptureResponse()
        body = mw(make_environ(), resp)
        assert resp.status == "200 OK"
        assert b"upstream" in b"".join(body)

    def test_challenge_bot(self) -> None:
        mw = TollboothWSGI(
            dummy_wsgi_app,
            secret=SECRET,
            policy=challenge_policy(),
        )
        resp = CaptureResponse()
        body = mw(
            make_environ(user_agent="Scrapy/2.0"),
            resp,
        )
        assert resp.status is not None
        assert "429" in resp.status
        html = b"".join(body).decode()
        assert "challenge" in html.lower()

    def test_verify_endpoint(self) -> None:
        mw = TollboothWSGI(
            dummy_wsgi_app,
            secret=SECRET,
            policy=challenge_policy(),
        )
        cid, nonce = solve_for_engine(mw.engine)
        form_body = (f"id={cid}&nonce={nonce}" f"&redirect=/home").encode()
        resp = CaptureResponse()
        mw(
            make_environ(
                method="POST",
                path=VERIFY_PATH,
                body=form_body,
            ),
            resp,
        )
        assert resp.status is not None
        assert "302" in resp.status
        assert resp.headers["Location"] == "/home"
        assert COOKIE_NAME in resp.headers["Set-Cookie"]

    def test_verify_invalid(self) -> None:
        mw = TollboothWSGI(dummy_wsgi_app, secret=SECRET)
        form_body = b"id=fake&nonce=0"
        resp = CaptureResponse()
        mw(
            make_environ(
                method="POST",
                path=VERIFY_PATH,
                body=form_body,
            ),
            resp,
        )
        assert resp.status is not None
        assert "403" in resp.status

    def test_cookie_bypass(self) -> None:
        mw = TollboothWSGI(
            dummy_wsgi_app,
            secret=SECRET,
            policy=challenge_policy(),
        )
        cid, nonce = solve_for_engine(mw.engine)
        request: Request = {
            "method": "GET",
            "remote_addr": "1.2.3.4",
            "headers": {},
            "cookies": {},
            "user_agent": "",
            "path": "/",
            "query": "",
            "form": {
                "id": cid,
                "nonce": nonce,
                "redirect": "/",
            },
        }
        _, headers, _ = mw.engine.handle_verify(request)
        cookie_val = headers["Set-Cookie"].split("=", 1)[1].split(";")[0]
        resp = CaptureResponse()
        body = mw(
            make_environ(cookie=f"{COOKIE_NAME}={cookie_val}"),
            resp,
        )
        assert resp.status == "200 OK"
        assert b"upstream" in b"".join(body)


class TestASGIMiddleware:
    @pytest.fixture
    def middleware(self) -> TollboothASGI:
        return TollboothASGI(
            dummy_asgi_app,
            secret=SECRET,
            policy=Policy(rules=[]),
        )

    @pytest.fixture
    def challenge_middleware(self) -> TollboothASGI:
        return TollboothASGI(
            dummy_asgi_app,
            secret=SECRET,
            policy=challenge_policy(),
        )

    def make_scope(
        self,
        method: str = "GET",
        path: str = "/",
        headers: list[list[bytes]] | None = None,
        client: tuple[str, int] = ("1.2.3.4", 0),
    ) -> dict[str, Any]:
        if headers is None:
            headers = [
                [b"user-agent", b"Mozilla/5.0"],
            ]
        return {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": b"",
            "headers": headers,
            "client": client,
        }

    async def collect_response(
        self,
        middleware: TollboothASGI,
        scope: dict[str, Any],
    ) -> tuple[int | None, dict[str, str], bytes]:
        messages: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        async def send(
            message: dict[str, Any],
        ) -> None:
            messages.append(message)

        await middleware(scope, receive, send)

        status: int | None = None
        headers: dict[str, str] = {}
        body = b""

        for msg in messages:
            if msg["type"] == "http.response.start":
                status = msg["status"]
                for pair in msg.get("headers", []):
                    key: str = (
                        pair[0].decode() if isinstance(pair[0], bytes) else pair[0]
                    )
                    val: str = (
                        pair[1].decode() if isinstance(pair[1], bytes) else pair[1]
                    )
                    headers[key] = val
            elif msg["type"] == "http.response.body":
                body += msg.get("body", b"")

        return status, headers, body

    async def test_pass_normal(
        self,
        middleware: TollboothASGI,
    ) -> None:
        status, _, body = await self.collect_response(
            middleware,
            self.make_scope(),
        )
        assert status == 200
        assert body == b"upstream"

    async def test_non_http_passes_through(
        self,
        middleware: TollboothASGI,
    ) -> None:
        called = False

        async def ws_app(
            _scope: dict[str, Any],
            _receive: Any,
            _send: Any,
        ) -> None:
            nonlocal called
            called = True

        mw = TollboothASGI(ws_app, secret=SECRET)
        scope: dict[str, Any] = {"type": "websocket"}

        async def noop() -> dict[str, Any]:
            return {}

        async def sink(
            _msg: dict[str, Any],
        ) -> None:
            pass

        await mw(scope, noop, sink)
        assert called

    async def test_challenge_bot(
        self,
        challenge_middleware: TollboothASGI,
    ) -> None:
        status, _, body = await self.collect_response(
            challenge_middleware,
            self.make_scope(headers=[[b"user-agent", b"Scrapy"]]),
        )
        assert status == 429
        assert "challenge" in body.decode().lower()

    async def test_verify_endpoint(
        self,
        challenge_middleware: TollboothASGI,
    ) -> None:
        engine = challenge_middleware.engine
        cid, nonce = solve_for_engine(engine)
        form_body = (f"id={cid}&nonce={nonce}&redirect=/ok").encode()
        body_sent = False

        async def receive() -> dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {
                    "type": "http.request",
                    "body": form_body,
                    "more_body": False,
                }
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        messages: list[dict[str, Any]] = []

        async def send(
            msg: dict[str, Any],
        ) -> None:
            messages.append(msg)

        scope = self.make_scope(
            method="POST",
            path=VERIFY_PATH,
        )
        await challenge_middleware(
            scope,
            receive,
            send,
        )
        assert messages[0]["status"] == 302
