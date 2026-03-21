import io
import json
import re
from typing import Any

import pytest

from tollbooth.engine import (
    COOKIE_NAME,
    Policy,
    Rule,
    _balloon,
    _count_leading_zero_bits,
)
from tollbooth.middleware import (
    VERIFY_PATH,
    TollboothASGI,
    TollboothWSGI,
)

SECRET = "e2e-test-secret-key-32-bytes!!!"


def upstream_wsgi(
    environ: dict[str, Any],
    start_response: Any,
) -> list[bytes]:
    path: str = str(environ.get("PATH_INFO", "/"))
    body = f"OK:{path}".encode()
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


async def upstream_asgi(
    scope: dict[str, Any],
    _receive: Any,
    send: Any,
) -> None:
    path: str = str(scope.get("path", "/"))
    body = f"OK:{path}".encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"text/plain"],
                [
                    b"content-length",
                    str(len(body)).encode(),
                ],
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": body,
        }
    )


MIXED_POLICY = Policy(
    rules=[
        Rule(
            name="search",
            action="allow",
            user_agent="Googlebot",
        ),
        Rule(
            name="bad",
            action="deny",
            user_agent="AhrefsBot",
        ),
        Rule(
            name="scraper",
            action="challenge",
            difficulty=1,
            user_agent="(?i:scrapy|python-requests)",
        ),
        Rule(
            name="health",
            action="allow",
            path="^/health$",
        ),
        Rule(
            name="dotenv",
            action="deny",
            path="/\\.env",
        ),
        Rule(
            name="curl",
            action="weigh",
            weight=3,
            user_agent="(?i:^curl/)",
        ),
        Rule(
            name="no-accept",
            action="weigh",
            weight=3,
            headers={"Accept": "^$"},
        ),
    ],
    challenge_threshold=5,
    default_difficulty=1,
)


def wsgi_request(
    app: TollboothWSGI,
    method: str = "GET",
    path: str = "/",
    user_agent: str = "Mozilla/5.0",
    remote_addr: str = "10.0.0.1",
    cookie: str = "",
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> tuple[str, dict[str, str], bytes]:
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
    for key, val in (headers or {}).items():
        env_key = f"HTTP_{key.upper().replace('-', '_')}"
        environ[env_key] = val

    captured: dict[str, Any] = {}

    def start_response(
        status: str,
        response_headers: list[tuple[str, str]],
    ) -> None:
        captured["status"] = status
        captured["headers"] = dict(response_headers)

    result = b"".join(app(environ, start_response))
    return (
        str(captured["status"]),
        dict(captured["headers"]),
        result,
    )


def extract_challenge_data(
    html: bytes,
) -> dict[str, Any] | None:
    match = re.search(
        r"JSON\.parse\('(.+?)'\)",
        html.decode(),
    )
    if not match:
        return None
    result: dict[str, Any] = json.loads(match.group(1))
    return result


def solve_pow(challenge: dict[str, Any]) -> str:
    for nonce in range(500_000):
        result = _balloon(
            challenge["data"],
            nonce,
            challenge["spaceCost"],
            challenge["timeCost"],
            challenge["delta"],
        )
        if _count_leading_zero_bits(result) >= (challenge["difficulty"]):
            return str(nonce)

    raise RuntimeError("unsolvable")


class TestE2EWSGI:
    @pytest.fixture
    def app(self) -> TollboothWSGI:
        return TollboothWSGI(
            upstream_wsgi,
            secret=SECRET,
            policy=MIXED_POLICY,
        )

    def test_browser_passes_through(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(app)
        assert "200" in status
        assert body == b"OK:/"

    def test_search_engine_allowed(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(
            app,
            user_agent="Googlebot/2.1",
        )
        assert "200" in status
        assert body == b"OK:/"

    def test_bad_bot_denied(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(
            app,
            user_agent="AhrefsBot/7.0",
        )
        assert "403" in status

    def test_health_endpoint_allowed(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(
            app,
            path="/health",
        )
        assert "200" in status

    def test_dotenv_denied(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, _ = wsgi_request(app, path="/.env")
        assert "403" in status

    def test_scraper_gets_challenge(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, headers, body = wsgi_request(
            app,
            user_agent="python-requests/2.28",
        )
        assert "429" in status
        assert "text/html" in headers["Content-Type"]
        challenge = extract_challenge_data(body)
        assert challenge is not None
        assert challenge["difficulty"] == 1

    def test_full_challenge_flow(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(
            app,
            user_agent="Scrapy/2.0",
        )
        assert "429" in status

        challenge = extract_challenge_data(body)
        assert challenge is not None
        nonce = solve_pow(challenge)
        form_body = (f"id={challenge['id']}&nonce={nonce}" f"&redirect=/api").encode()

        status, headers, _ = wsgi_request(
            app,
            method="POST",
            path=VERIFY_PATH,
            body=form_body,
        )
        assert "302" in status
        assert headers["Location"] == "/api"

        cookie_header = headers["Set-Cookie"]
        assert COOKIE_NAME in cookie_header
        cookie_val = cookie_header.split("=", 1)[1].split(";")[0]

        status, _, body = wsgi_request(
            app,
            path="/api",
            user_agent="Scrapy/2.0",
            cookie=f"{COOKIE_NAME}={cookie_val}",
        )
        assert "200" in status
        assert body == b"OK:/api"

    def test_weight_accumulation_triggers_challenge(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(
            app,
            user_agent="curl/7.88",
            headers={"Accept": ""},
        )
        assert "429" in status

    def test_single_weight_rule_passes(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(
            app,
            user_agent="curl/7.88",
            headers={"Accept": "text/html"},
        )
        assert "200" in status

    def test_challenge_replay_rejected(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(
            app,
            user_agent="Scrapy/2.0",
        )
        challenge = extract_challenge_data(body)
        assert challenge is not None
        nonce = solve_pow(challenge)
        form_body = (f"id={challenge['id']}&nonce={nonce}" f"&redirect=/").encode()

        _ = wsgi_request(
            app,
            method="POST",
            path=VERIFY_PATH,
            body=form_body,
        )
        status, _, _ = wsgi_request(
            app,
            method="POST",
            path=VERIFY_PATH,
            body=form_body,
        )
        assert "403" in status

    def test_challenge_ip_mismatch_rejected(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(
            app,
            user_agent="Scrapy/2.0",
            remote_addr="10.0.0.1",
        )
        challenge = extract_challenge_data(body)
        assert challenge is not None
        nonce = solve_pow(challenge)
        form_body = (f"id={challenge['id']}&nonce={nonce}" f"&redirect=/").encode()

        status, _, _ = wsgi_request(
            app,
            method="POST",
            path=VERIFY_PATH,
            body=form_body,
            remote_addr="99.99.99.99",
        )
        assert "403" in status

    def test_cookie_from_different_ip_rejected(
        self,
        app: TollboothWSGI,
    ) -> None:
        status, _, body = wsgi_request(
            app,
            user_agent="Scrapy/2.0",
            remote_addr="10.0.0.1",
        )
        challenge = extract_challenge_data(body)
        assert challenge is not None
        nonce = solve_pow(challenge)
        form_body = (f"id={challenge['id']}&nonce={nonce}" f"&redirect=/").encode()

        _, headers, _ = wsgi_request(
            app,
            method="POST",
            path=VERIFY_PATH,
            body=form_body,
            remote_addr="10.0.0.1",
        )
        cookie_val = headers["Set-Cookie"].split("=", 1)[1].split(";")[0]

        status, _, _ = wsgi_request(
            app,
            user_agent="Scrapy/2.0",
            remote_addr="10.0.0.2",
            cookie=f"{COOKIE_NAME}={cookie_val}",
        )
        assert "429" in status

    def test_security_headers_present(
        self,
        app: TollboothWSGI,
    ) -> None:
        _, headers, _ = wsgi_request(
            app,
            user_agent="Scrapy/2.0",
        )
        assert headers["Cache-Control"] == "no-store"
        assert "nosniff" in (headers["X-Content-Type-Options"])
        assert "Content-Security-Policy" in headers

    def test_cookie_attributes(
        self,
        app: TollboothWSGI,
    ) -> None:
        _, _, body = wsgi_request(
            app,
            user_agent="Scrapy/2.0",
        )
        challenge = extract_challenge_data(body)
        assert challenge is not None
        nonce = solve_pow(challenge)
        form_body = (f"id={challenge['id']}&nonce={nonce}" f"&redirect=/").encode()

        _, headers, _ = wsgi_request(
            app,
            method="POST",
            path=VERIFY_PATH,
            body=form_body,
        )
        cookie = headers["Set-Cookie"]
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=Strict" in cookie

    def test_multiple_paths_same_cookie(
        self,
        app: TollboothWSGI,
    ) -> None:
        _, _, body = wsgi_request(
            app,
            user_agent="Scrapy/2.0",
            path="/",
        )
        challenge = extract_challenge_data(body)
        assert challenge is not None
        nonce = solve_pow(challenge)
        form_body = (f"id={challenge['id']}&nonce={nonce}" f"&redirect=/").encode()

        _, headers, _ = wsgi_request(
            app,
            method="POST",
            path=VERIFY_PATH,
            body=form_body,
        )
        cookie_val = headers["Set-Cookie"].split("=", 1)[1].split(";")[0]
        cookie_str = f"{COOKIE_NAME}={cookie_val}"

        for test_path in ["/", "/api", "/page"]:
            status, _, body = wsgi_request(
                app,
                path=test_path,
                user_agent="Scrapy/2.0",
                cookie=cookie_str,
            )
            assert "200" in status
            assert body == f"OK:{test_path}".encode()


class TestE2EASGI:
    @pytest.fixture
    def app(self) -> TollboothASGI:
        return TollboothASGI(
            upstream_asgi,
            secret=SECRET,
            policy=MIXED_POLICY,
        )

    def make_scope(
        self,
        method: str = "GET",
        path: str = "/",
        headers: list[list[bytes]] | None = None,
        client: tuple[str, int] = ("10.0.0.1", 12345),
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

    async def do_request(
        self,
        app: TollboothASGI,
        scope: dict[str, Any],
        body: bytes = b"",
    ) -> tuple[int | None, dict[str, str], bytes]:
        body_sent = False
        messages: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        async def send(
            msg: dict[str, Any],
        ) -> None:
            messages.append(msg)

        await app(scope, receive, send)

        status: int | None = None
        resp_headers: dict[str, str] = {}
        response_body = b""

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
                    resp_headers[key] = val
            elif msg["type"] == "http.response.body":
                response_body += msg.get("body", b"")

        return status, resp_headers, response_body

    async def test_browser_passes(
        self,
        app: TollboothASGI,
    ) -> None:
        status, _, body = await self.do_request(
            app,
            self.make_scope(),
        )
        assert status == 200
        assert body == b"OK:/"

    async def test_bot_challenged(
        self,
        app: TollboothASGI,
    ) -> None:
        scope = self.make_scope(headers=[[b"user-agent", b"Scrapy/2.0"]])
        status, _, _ = await self.do_request(app, scope)
        assert status == 429

    async def test_full_flow(
        self,
        app: TollboothASGI,
    ) -> None:
        scope = self.make_scope(headers=[[b"user-agent", b"Scrapy/2.0"]])
        _, _, body = await self.do_request(app, scope)

        challenge = extract_challenge_data(body)
        assert challenge is not None
        nonce = solve_pow(challenge)
        form_body = (f"id={challenge['id']}&nonce={nonce}" f"&redirect=/done").encode()

        verify_scope = self.make_scope(
            method="POST",
            path=VERIFY_PATH,
        )
        status, headers, _ = await self.do_request(
            app,
            verify_scope,
            body=form_body,
        )
        assert status == 302
        assert headers["Location"] == "/done"

        cookie_val = headers["Set-Cookie"].split("=", 1)[1].split(";")[0]
        scope = self.make_scope(
            headers=[
                [b"user-agent", b"Scrapy/2.0"],
                [
                    b"cookie",
                    f"{COOKIE_NAME}={cookie_val}".encode(),
                ],
            ]
        )
        status, _, body = await self.do_request(
            app,
            scope,
        )
        assert status == 200
        assert body == b"OK:/"

    async def test_denied_bot(
        self,
        app: TollboothASGI,
    ) -> None:
        scope = self.make_scope(
            headers=[
                [b"user-agent", b"AhrefsBot/7.0"],
            ]
        )
        status, _, _ = await self.do_request(app, scope)
        assert status == 403
