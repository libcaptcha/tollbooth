import json
import re
from urllib.parse import urlencode

import pytest

from tollbooth.engine import (
    COOKIE_NAME,
    Policy,
    Rule,
    _balloon,
    _count_leading_zero_bits,
)
from tollbooth.integrations.base import TollboothBase, resolve_base

SECRET = "test-secret-key-32-bytes-long!!!"


def make_request(
    method="GET",
    path="/",
    user_agent="Mozilla/5.0",
    remote_addr="1.2.3.4",
    headers=None,
    cookies=None,
    form=None,
):
    return {
        "method": method,
        "user_agent": user_agent,
        "path": path,
        "query": "",
        "remote_addr": remote_addr,
        "headers": headers or {},
        "cookies": cookies or {},
        "form": form or {},
    }


def challenge_policy():
    return Policy(
        rules=[
            Rule(
                name="all",
                action="challenge",
                difficulty=1,
            ),
        ]
    )


def deny_policy():
    return Policy(
        rules=[
            Rule(
                name="bad",
                action="deny",
                user_agent="BadBot",
            ),
        ]
    )


def solve(engine, remote_addr="1.2.3.4"):
    request = make_request(remote_addr=remote_addr)
    challenge = engine.issue_challenge(1, request)
    p = engine.policy
    for nonce in range(200_000):
        result = _balloon(
            challenge.random_data,
            nonce,
            p.space_cost,
            p.time_cost,
            p.delta,
        )
        if _count_leading_zero_bits(result) >= 1:
            return challenge.id, str(nonce)
    raise RuntimeError("unsolvable")


def extract_challenge(html):
    if isinstance(html, bytes):
        html = html.decode()
    match = re.search(
        r"JSON\.parse\('(.+?)'\)",
        html,
    )
    return json.loads(match.group(1)) if match else None


def solve_pow(challenge):
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


class TestBase:
    def make_tb(self, **kwargs):
        policy = kwargs.pop(
            "policy",
            Policy(rules=[]),
        )
        return TollboothBase(
            secret=SECRET,
            policy=policy,
            **kwargs,
        )

    def test_allows_normal(self):
        tb = self.make_tb()
        assert (
            tb.process_request(
                make_request(),
            )
            is None
        )

    def test_denies(self):
        tb = self.make_tb(policy=deny_policy())
        result = tb.process_request(
            make_request(user_agent="BadBot"),
        )
        assert result.status == 403
        assert result.body == "Forbidden"

    def test_challenges_html(self):
        tb = self.make_tb(policy=challenge_policy())
        result = tb.process_request(make_request())
        assert result.status == 429
        assert "challenge" in result.body.lower()

    def test_exclude(self):
        tb = self.make_tb(
            policy=challenge_policy(),
            exclude=[r"^/health"],
        )
        assert (
            tb.process_request(
                make_request(path="/health"),
            )
            is None
        )
        assert (
            tb.process_request(
                make_request(path="/api"),
            ).status
            == 429
        )

    def test_cookie_bypass(self):
        tb = self.make_tb(policy=challenge_policy())
        cid, nonce = solve(tb.engine)
        result = tb.process_request(
            make_request(
                method="POST",
                path=tb.verify_path,
                form={
                    "id": cid,
                    "nonce": nonce,
                    "redirect": "/",
                },
            )
        )
        assert result.status == 302
        cookie_val = result.headers["Set-Cookie"].split("=", 1)[1].split(";")[0]
        assert (
            tb.process_request(
                make_request(
                    cookies={COOKIE_NAME: cookie_val},
                )
            )
            is None
        )

    def test_json_challenge(self):
        tb = self.make_tb(
            json_mode=True,
            policy=challenge_policy(),
        )
        result = tb.process_request(make_request())
        assert result.status == 429
        data = json.loads(result.body)
        assert "id" in data["challenge"]
        assert data["challenge"]["difficulty"] == 1
        assert result.headers["Content-Type"] == "application/json"

    def test_json_deny(self):
        tb = self.make_tb(
            json_mode=True,
            policy=deny_policy(),
        )
        result = tb.process_request(
            make_request(user_agent="BadBot"),
        )
        assert result.status == 403
        assert json.loads(result.body)["error"] == "forbidden"

    def test_json_verify_success(self):
        tb = self.make_tb(json_mode=True)
        cid, nonce = solve(tb.engine)
        result = tb.process_request(
            make_request(
                method="POST",
                path=tb.verify_path,
                form={
                    "id": cid,
                    "nonce": nonce,
                    "redirect": "/",
                },
            )
        )
        assert result.status == 200
        assert "token" in json.loads(result.body)

    def test_json_verify_failure(self):
        tb = self.make_tb(json_mode=True)
        result = tb.process_request(
            make_request(
                method="POST",
                path=tb.verify_path,
                form={"id": "fake", "nonce": "0"},
            )
        )
        assert result.status == 403
        assert json.loads(result.body)["error"] == "invalid"

    def test_html_verify_success(self):
        tb = self.make_tb()
        cid, nonce = solve(tb.engine)
        result = tb.process_request(
            make_request(
                method="POST",
                path=tb.verify_path,
                form={
                    "id": cid,
                    "nonce": nonce,
                    "redirect": "/ok",
                },
            )
        )
        assert result.status == 302
        assert result.headers["Location"] == "/ok"
        assert COOKIE_NAME in result.headers["Set-Cookie"]

    def test_html_verify_failure(self):
        tb = self.make_tb()
        result = tb.process_request(
            make_request(
                method="POST",
                path=tb.verify_path,
                form={"id": "fake", "nonce": "0"},
            )
        )
        assert result.status == 403
        assert result.body == "Invalid"

    def test_redirect_sanitization(self):
        tb = self.make_tb()
        cid, nonce = solve(tb.engine)
        for bad in [
            "//evil.com",
            "https://evil.com",
            "javascript:alert(1)",
        ]:
            stored = tb.engine.store.get(cid)
            stored.spent = False
            result = tb.process_request(
                make_request(
                    method="POST",
                    path=tb.verify_path,
                    form={
                        "id": cid,
                        "nonce": nonce,
                        "redirect": bad,
                    },
                )
            )
            assert result.headers["Location"] == "/"

    def test_is_verify(self):
        tb = self.make_tb()
        assert tb.is_verify("POST", tb.verify_path)
        assert not tb.is_verify("GET", tb.verify_path)
        assert not tb.is_verify("POST", "/other")

    def test_is_excluded(self):
        tb = self.make_tb(
            exclude=[r"^/static/", r"^/health$"],
        )
        assert tb.is_excluded("/static/foo.js")
        assert tb.is_excluded("/health")
        assert not tb.is_excluded("/api")

    def testresolve_with_secret(self):
        assert isinstance(
            resolve_base(SECRET, {}),
            TollboothBase,
        )

    def testresolve_with_instance(self):
        tb = TollboothBase(secret=SECRET)
        assert resolve_base(tb, {}) is tb


# --- Flask ---

try:
    import flask

    from tollbooth.integrations.flask import Tollbooth, tollbooth_protect

    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


@pytest.mark.skipif(
    not HAS_FLASK,
    reason="flask not installed",
)
class TestFlask:
    def make_app(self, **tb_kwargs):
        tb_kwargs.setdefault(
            "policy",
            Policy(rules=[]),
        )
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        tb = Tollbooth(
            app,
            secret=SECRET,
            **tb_kwargs,
        )

        @app.route("/")
        def index():
            return "OK"

        @app.route("/public")
        @tb.exempt
        def public():
            return "public"

        return app, tb

    def test_allows_normal(self):
        app, _ = self.make_app()
        with app.test_client() as c:
            assert c.get("/").status_code == 200

    def test_challenges(self):
        app, _ = self.make_app(
            policy=challenge_policy(),
        )
        with app.test_client() as c:
            assert c.get("/").status_code == 429

    def test_exempt_skips(self):
        app, _ = self.make_app(
            policy=challenge_policy(),
        )
        with app.test_client() as c:
            resp = c.get("/public")
            assert resp.status_code == 200
            assert resp.data == b"public"

    def test_denies_bad_bot(self):
        app, _ = self.make_app(policy=deny_policy())
        with app.test_client() as c:
            resp = c.get(
                "/",
                headers={"User-Agent": "BadBot"},
            )
            assert resp.status_code == 403

    def test_verify_flow(self):
        app, tb = self.make_app(
            policy=challenge_policy(),
        )
        with app.test_client() as c:
            resp = c.get("/")
            assert resp.status_code == 429
            challenge = extract_challenge(resp.data)
            assert challenge is not None
            nonce = solve_pow(challenge)
            resp = c.post(
                tb._tb.verify_path,
                data={
                    "id": challenge["id"],
                    "nonce": nonce,
                    "redirect": "/",
                },
            )
            assert resp.status_code == 302

    def test_standalone_protect(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        protect = tollbooth_protect(
            SECRET,
            policy=challenge_policy(),
        )

        @app.route("/protected")
        @protect
        def protected():
            return "secret"

        @app.route("/open")
        def open_route():
            return "open"

        with app.test_client() as c:
            assert c.get("/protected").status_code == 429
            assert c.get("/open").status_code == 200

    def test_init_app_deferred(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        tb = Tollbooth(
            secret=SECRET,
            policy=Policy(rules=[]),
        )

        @app.route("/")
        def index():
            return "OK"

        tb.init_app(app)
        assert "tollbooth" in app.extensions
        with app.test_client() as c:
            assert c.get("/").status_code == 200

    def test_protect_method(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        tb = Tollbooth(
            secret=SECRET,
            policy=challenge_policy(),
        )

        @app.route("/guarded")
        @tb.protect
        def guarded():
            return "guarded"

        with app.test_client() as c:
            assert c.get("/guarded").status_code == 429


# --- FastAPI ---

try:
    from tollbooth.integrations.fastapi import TollboothDep
    from tollbooth.integrations.fastapi import TollboothMiddleware as FastAPIMW

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


@pytest.mark.skipif(
    not HAS_FASTAPI,
    reason="fastapi not installed",
)
class TestFastAPI:
    async def test_middleware_json_challenge(self):
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        app = FastAPI()
        app.add_middleware(
            FastAPIMW,
            secret=SECRET,
            policy=challenge_policy(),
        )

        @app.get("/")
        async def index():
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as c:
            resp = await c.get("/")
            assert resp.status_code == 429
            assert "challenge" in resp.json()

    async def test_middleware_allows_normal(self):
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        app = FastAPI()
        app.add_middleware(
            FastAPIMW,
            secret=SECRET,
            policy=Policy(rules=[]),
        )

        @app.get("/")
        async def index():
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as c:
            resp = await c.get("/")
            assert resp.status_code == 200

    async def test_dep_blocks(self):
        from fastapi import Depends, FastAPI
        from httpx import ASGITransport, AsyncClient

        app = FastAPI()
        dep = TollboothDep(
            SECRET,
            policy=challenge_policy(),
        )

        @app.get(
            "/",
            dependencies=[Depends(dep)],
        )
        async def index():
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as c:
            resp = await c.get("/")
            assert resp.status_code == 429

    async def test_dep_passes_normal(self):
        from fastapi import Depends, FastAPI
        from httpx import ASGITransport, AsyncClient

        app = FastAPI()
        dep = TollboothDep(
            SECRET,
            policy=Policy(rules=[]),
        )

        @app.get(
            "/",
            dependencies=[Depends(dep)],
        )
        async def index():
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as c:
            resp = await c.get("/")
            assert resp.status_code == 200


# --- Django ---

try:
    import django
    from django.conf import settings as django_settings

    if not django_settings.configured:
        django_settings.configure(
            SECRET_KEY="django-test",
            ROOT_URLCONF="tests.test_integrations",
            TOLLBOOTH={
                "secret": SECRET,
                "policy": challenge_policy(),
            },
        )
        django.setup()

    from django.http import HttpResponse as DjangoResponse
    from django.test import RequestFactory
    from django.urls import path

    from tollbooth.integrations.django import TollboothMiddleware as DjangoMW
    from tollbooth.integrations.django import (
        make_middleware,
        make_verify_view,
        tollbooth_exempt,
    )
    from tollbooth.integrations.django import tollbooth_protect as django_protect

    def _index_view(request):
        return DjangoResponse("OK")

    @tollbooth_exempt
    def _exempt_view(request):
        return DjangoResponse("exempt")

    urlpatterns = [
        path("", _index_view),
        path("exempt/", _exempt_view),
    ]

    HAS_DJANGO = True
except ImportError:
    HAS_DJANGO = False


@pytest.mark.skipif(
    not HAS_DJANGO,
    reason="django not installed",
)
class TestDjango:
    def setup_method(self):
        self.factory = RequestFactory()

    def test_make_middleware_allows(self):
        MW = make_middleware(
            SECRET,
            policy=Policy(rules=[]),
        )
        mw = MW(lambda r: DjangoResponse("OK"))
        resp = mw(self.factory.get("/"))
        assert resp.status_code == 200

    def test_make_middleware_challenges(self):
        MW = make_middleware(
            SECRET,
            policy=challenge_policy(),
        )
        mw = MW(lambda r: DjangoResponse("OK"))
        resp = mw(self.factory.get("/"))
        assert resp.status_code == 429

    def test_settings_middleware(self):
        mw = DjangoMW(lambda r: DjangoResponse("OK"))
        resp = mw(self.factory.get("/"))
        assert resp.status_code == 429

    def test_exempt_view(self):
        mw = DjangoMW(lambda r: DjangoResponse("OK"))
        resp = mw(self.factory.get("/exempt/"))
        assert resp.status_code == 200

    def test_protect_decorator(self):
        protect = django_protect(
            SECRET,
            policy=challenge_policy(),
        )

        @protect
        def view(request):
            return DjangoResponse("secret")

        resp = view(self.factory.get("/"))
        assert resp.status_code == 429

    def test_verify_flow(self):
        MW = make_middleware(
            SECRET,
            policy=challenge_policy(),
        )
        mw = MW(lambda r: DjangoResponse("OK"))
        resp = mw(self.factory.get("/"))
        assert resp.status_code == 429
        challenge = extract_challenge(resp.content)
        assert challenge is not None
        nonce = solve_pow(challenge)
        resp = mw(
            self.factory.post(
                "/.tollbooth/verify",
                data={
                    "id": challenge["id"],
                    "nonce": nonce,
                    "redirect": "/",
                },
            )
        )
        assert resp.status_code == 302

    def test_make_verify_view(self):
        tb = TollboothBase(secret=SECRET)
        view = make_verify_view(tb)
        cid, nonce = solve(
            tb.engine,
            remote_addr="127.0.0.1",
        )
        req = self.factory.post(
            "/.tollbooth/verify",
            data={
                "id": cid,
                "nonce": nonce,
                "redirect": "/done",
            },
        )
        resp = view(req)
        assert resp.status_code == 302


# --- Falcon ---

try:
    import falcon
    import falcon.testing

    from tollbooth.integrations.falcon import TollboothMiddleware as FalconMW
    from tollbooth.integrations.falcon import VerifyResource, tollbooth_hook

    class _IndexResource:
        def on_get(self, req, resp):
            resp.text = "OK"

    HAS_FALCON = True
except ImportError:
    HAS_FALCON = False


@pytest.mark.skipif(
    not HAS_FALCON,
    reason="falcon not installed",
)
class TestFalcon:
    def make_client(self, **mw_kwargs):
        policy = mw_kwargs.pop(
            "policy",
            Policy(rules=[]),
        )
        mw = FalconMW(
            SECRET,
            policy=policy,
            **mw_kwargs,
        )
        app = falcon.App(middleware=[mw])
        app.add_route("/", _IndexResource())
        return falcon.testing.TestClient(app)

    def test_allows_normal(self):
        c = self.make_client()
        result = c.simulate_get("/")
        assert result.status == falcon.HTTP_200

    def test_challenges(self):
        c = self.make_client(
            policy=challenge_policy(),
        )
        result = c.simulate_get("/")
        assert "429" in result.status

    def test_denies_bad_bot(self):
        c = self.make_client(policy=deny_policy())
        result = c.simulate_get(
            "/",
            headers={"User-Agent": "BadBot"},
        )
        assert "403" in result.status

    def test_verify_flow(self):
        mw = FalconMW(
            SECRET,
            policy=challenge_policy(),
        )
        app = falcon.App(middleware=[mw])
        app.add_route("/", _IndexResource())
        c = falcon.testing.TestClient(app)

        result = c.simulate_get("/")
        assert "429" in result.status
        challenge = extract_challenge(result.text)
        assert challenge is not None
        nonce = solve_pow(challenge)
        result = c.simulate_post(
            "/.tollbooth/verify",
            body=urlencode(
                {
                    "id": challenge["id"],
                    "nonce": nonce,
                    "redirect": "/",
                }
            ),
            headers={
                "Content-Type": ("application/x-www-form-urlencoded"),
            },
        )
        assert "302" in result.status

    def test_hook_blocks(self):
        hook = tollbooth_hook(
            SECRET,
            policy=challenge_policy(),
        )

        class Protected:
            @falcon.before(hook)
            def on_get(self, req, resp):
                resp.text = "secret"

        app = falcon.App()
        app.add_route("/", Protected())
        c = falcon.testing.TestClient(app)
        result = c.simulate_get("/")
        assert "429" in result.status

    def test_verify_resource(self):
        tb = TollboothBase(secret=SECRET)
        cid, nonce = solve(
            tb.engine,
            remote_addr="127.0.0.1",
        )
        app = falcon.App()
        app.add_route(
            "/.tollbooth/verify",
            VerifyResource(tb),
        )
        c = falcon.testing.TestClient(app)
        result = c.simulate_post(
            "/.tollbooth/verify",
            body=urlencode(
                {
                    "id": cid,
                    "nonce": nonce,
                    "redirect": "/done",
                }
            ),
            headers={
                "Content-Type": ("application/x-www-form-urlencoded"),
            },
        )
        assert "302" in result.status
