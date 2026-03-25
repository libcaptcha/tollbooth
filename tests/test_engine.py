import time
from typing import Any

import pytest

from tollbooth.challenges.base import (
    count_leading_zero_bits as _count_leading_zero_bits,
)
from tollbooth.challenges.sha256_balloon import _balloon
from tollbooth.engine import (
    CHALLENGE_TTL,
    COOKIE_NAME,
    Challenge,
    Engine,
    Policy,
    Request,
    Rule,
    Store,
    jwt_decode,
    jwt_encode,
    load_policy,
)

SECRET = "test-secret-key-32-bytes-long!!!"


def make_request(
    user_agent: str = "Mozilla/5.0",
    path: str = "/",
    remote_addr: str = "1.2.3.4",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    form: dict[str, str] | None = None,
) -> Request:
    return {
        "method": "GET",
        "user_agent": user_agent,
        "path": path,
        "query": "",
        "remote_addr": remote_addr,
        "headers": headers or {},
        "cookies": cookies or {},
        "form": form or {},
    }


def solve_challenge(
    engine: Engine,
    request: Request,
) -> tuple[str, str]:
    from tollbooth.challenges import SHA256Balloon

    challenge = engine.issue_challenge(1, request)
    handler = engine.policy.challenge_handler
    assert isinstance(handler, SHA256Balloon)

    for nonce in range(200_000):
        result = _balloon(
            challenge.random_data,
            nonce,
            handler.space_cost,
            handler.time_cost,
            handler.delta,
        )
        if _count_leading_zero_bits(result) >= 1:
            return challenge.id, str(nonce)

    raise RuntimeError("failed to solve")


class TestJWT:
    def test_encode_decode(self) -> None:
        secret = b"secret-key-32-bytes-long!!!!!!!!"
        claims: dict[str, Any] = {
            "sub": "test",
            "exp": int(time.time()) + 3600,
        }
        token = jwt_encode(claims, secret)
        decoded = jwt_decode(token, secret)
        assert decoded["sub"] == "test"

    def test_expired_token(self) -> None:
        secret = b"secret-key-32-bytes-long!!!!!!!!"
        claims: dict[str, Any] = {
            "exp": int(time.time()) - 1,
        }
        token = jwt_encode(claims, secret)
        with pytest.raises(ValueError, match="expired"):
            jwt_decode(token, secret)

    def test_invalid_signature(self) -> None:
        secret = b"secret-key-32-bytes-long!!!!!!!!"
        claims: dict[str, Any] = {
            "exp": int(time.time()) + 3600,
        }
        token = jwt_encode(claims, secret)
        with pytest.raises(ValueError, match="signature"):
            jwt_decode(
                token,
                b"wrong-key-32-bytes!!!!!!!!!!!!!!!",
            )

    def test_malformed_token(self) -> None:
        with pytest.raises(ValueError, match="invalid"):
            jwt_decode("not.a.valid.token", b"key")

    def test_tampered_payload(self) -> None:
        secret = b"secret-key-32-bytes-long!!!!!!!!"
        claims: dict[str, Any] = {
            "exp": int(time.time()) + 3600,
        }
        token = jwt_encode(claims, secret)
        parts = token.split(".")
        parts[1] = parts[1][::-1]
        tampered = ".".join(parts)
        with pytest.raises(ValueError):
            jwt_decode(tampered, secret)


class TestStore:
    def test_set_and_get(self) -> None:
        store = Store()
        challenge = Challenge(
            id="abc",
            random_data="ff",
            difficulty=1,
            ip_hash="x",
            created_at=time.time(),
        )
        store.set(challenge)
        assert store.get("abc") is challenge

    def test_missing_key(self) -> None:
        store = Store()
        assert store.get("nonexistent") is None

    def test_expiry(self) -> None:
        store = Store()
        challenge = Challenge(
            id="old",
            random_data="ff",
            difficulty=1,
            ip_hash="x",
            created_at=time.time() - CHALLENGE_TTL - 1,
        )
        store.set(challenge)
        assert store.get("old") is None


class TestRule:
    def test_user_agent_match(self) -> None:
        rule = Rule(name="test", user_agent="(?i:scrapy)")
        assert rule.matches(make_request(user_agent="Scrapy/2.0"))
        assert not rule.matches(make_request(user_agent="Mozilla/5.0"))

    def test_path_match(self) -> None:
        rule = Rule(name="test", path="/admin")
        assert rule.matches(make_request(path="/admin"))
        assert not rule.matches(make_request(path="/"))

    def test_header_match(self) -> None:
        rule = Rule(name="test", headers={"Accept": "^$"})
        assert rule.matches(make_request(headers={"Accept": ""}))
        assert not rule.matches(make_request(headers={"Accept": "text/html"}))

    def test_cidr_match(self) -> None:
        rule = Rule(
            name="test",
            remote_addresses=["10.0.0.0/8"],
        )
        assert rule.matches(make_request(remote_addr="10.1.2.3"))
        assert not rule.matches(make_request(remote_addr="192.168.1.1"))

    def test_ipv6_cidr(self) -> None:
        rule = Rule(
            name="test",
            remote_addresses=["2001:db8::/32"],
        )
        assert rule.matches(make_request(remote_addr="2001:db8::1"))
        assert not rule.matches(make_request(remote_addr="2001:db9::1"))

    def test_invalid_ip(self) -> None:
        rule = Rule(
            name="test",
            remote_addresses=["10.0.0.0/8"],
        )
        assert not rule.matches(make_request(remote_addr="not-an-ip"))

    def test_empty_ua_match(self) -> None:
        rule = Rule(name="test", user_agent="^$")
        assert rule.matches(make_request(user_agent=""))
        assert not rule.matches(make_request(user_agent="Bot"))

    def test_multi_criteria(self) -> None:
        rule = Rule(
            name="test",
            user_agent="curl",
            path="/api",
        )
        assert rule.matches(make_request(user_agent="curl/7.0", path="/api/v1"))
        assert not rule.matches(make_request(user_agent="curl/7.0", path="/home"))

    def test_no_criteria_matches_all(self) -> None:
        rule = Rule(name="test")
        assert rule.matches(make_request())


class TestPolicy:
    def test_allow_rule(self) -> None:
        policy = Policy(
            rules=[
                Rule(
                    name="bot",
                    action="allow",
                    user_agent="Googlebot",
                ),
            ]
        )
        action, _ = policy.evaluate(make_request(user_agent="Googlebot/2.1"))
        assert action == "allow"

    def test_deny_rule(self) -> None:
        policy = Policy(
            rules=[
                Rule(
                    name="bad",
                    action="deny",
                    user_agent="AhrefsBot",
                ),
            ]
        )
        action, _ = policy.evaluate(make_request(user_agent="AhrefsBot/7.0"))
        assert action == "deny"

    def test_challenge_rule(self) -> None:
        policy = Policy(
            rules=[
                Rule(
                    name="scraper",
                    action="challenge",
                    difficulty=8,
                    user_agent="Scrapy",
                ),
            ]
        )
        action, diff = policy.evaluate(make_request(user_agent="Scrapy/2.0"))
        assert action == "challenge"
        assert diff == 8

    def test_challenge_uses_default_difficulty(
        self,
    ) -> None:
        policy = Policy(
            rules=[
                Rule(
                    name="test",
                    action="challenge",
                    user_agent="test",
                ),
            ],
            default_difficulty=6,
        )
        _, diff = policy.evaluate(make_request(user_agent="test"))
        assert diff == 6

    def test_weight_accumulation(self) -> None:
        policy = Policy(
            rules=[
                Rule(
                    name="w1",
                    action="weigh",
                    weight=3,
                    user_agent="curl",
                ),
                Rule(
                    name="w2",
                    action="weigh",
                    weight=3,
                    headers={"Accept": "^$"},
                ),
            ],
            challenge_threshold=5,
        )
        request = make_request(
            user_agent="curl/7",
            headers={"Accept": ""},
        )
        action, _ = policy.evaluate(request)
        assert action == "challenge"

    def test_weight_below_threshold(self) -> None:
        policy = Policy(
            rules=[
                Rule(
                    name="w1",
                    action="weigh",
                    weight=2,
                    user_agent="curl",
                ),
            ],
            challenge_threshold=5,
        )
        action, _ = policy.evaluate(make_request(user_agent="curl/7"))
        assert action == "allow"

    def test_first_match_wins(self) -> None:
        policy = Policy(
            rules=[
                Rule(
                    name="allow",
                    action="allow",
                    user_agent="Bot",
                ),
                Rule(
                    name="deny",
                    action="deny",
                    user_agent="Bot",
                ),
            ]
        )
        action, _ = policy.evaluate(make_request(user_agent="Bot"))
        assert action == "allow"

    def test_no_match_allows(self) -> None:
        policy = Policy(
            rules=[
                Rule(
                    name="specific",
                    action="deny",
                    user_agent="SomeBot",
                ),
            ]
        )
        action, _ = policy.evaluate(make_request(user_agent="Mozilla/5.0"))
        assert action == "allow"

    def test_load_default_policy(self) -> None:
        policy = load_policy()
        assert len(policy.rules) > 0
        assert policy.challenge_threshold == 5


class TestEngine:
    def make_engine(self, **kwargs: Any) -> Engine:
        policy = kwargs.pop("policy", None)
        if policy is None:
            policy = Policy(rules=[])
        return Engine(secret=SECRET, policy=policy, **kwargs)

    def test_process_allows_normal_request(
        self,
    ) -> None:
        engine = self.make_engine()
        action, _, _, _ = engine.process(make_request())
        assert action == "pass"

    def test_process_denies_bad_bot(self) -> None:
        engine = self.make_engine(
            policy=Policy(
                rules=[
                    Rule(
                        name="bad",
                        action="deny",
                        user_agent="BadBot",
                    ),
                ]
            )
        )
        action, status, _, body = engine.process(make_request(user_agent="BadBot/1.0"))
        assert action == "deny"
        assert status == 403
        assert body == "Forbidden"

    def test_process_challenges_scraper(
        self,
    ) -> None:
        engine = self.make_engine(
            policy=Policy(
                rules=[
                    Rule(
                        name="s",
                        action="challenge",
                        difficulty=2,
                        user_agent="Scrapy",
                    ),
                ]
            )
        )
        action, status, headers, body = engine.process(
            make_request(user_agent="Scrapy/2.0")
        )
        assert action == "challenge"
        assert status == 200
        assert "challenge" in body.lower()
        assert headers["Cache-Control"] == "no-store"
        assert "Content-Security-Policy" in headers

    def test_issue_and_validate_challenge(
        self,
    ) -> None:
        engine = self.make_engine()
        request = make_request()
        cid, nonce = solve_challenge(engine, request)
        token = engine.validate_challenge(cid, nonce, request)
        assert token is not None
        assert len(token.split(".")) == 3

    def test_challenge_single_use(self) -> None:
        engine = self.make_engine()
        request = make_request()
        cid, nonce = solve_challenge(engine, request)
        engine.validate_challenge(cid, nonce, request)
        again = engine.validate_challenge(cid, nonce, request)
        assert again is None

    def test_challenge_ip_binding(self) -> None:
        engine = self.make_engine()
        request = make_request(remote_addr="1.2.3.4")
        cid, nonce = solve_challenge(engine, request)
        other_ip = make_request(remote_addr="5.6.7.8")
        token = engine.validate_challenge(cid, nonce, other_ip)
        assert token is None

    def test_invalid_nonce(self) -> None:
        engine = self.make_engine()
        request = make_request()
        challenge = engine.issue_challenge(1, request)
        token = engine.validate_challenge(
            challenge.id,
            "not-a-number",
            request,
        )
        assert token is None

    def test_nonexistent_challenge(self) -> None:
        engine = self.make_engine()
        token = engine.validate_challenge(
            "nonexistent",
            "0",
            make_request(),
        )
        assert token is None

    def test_cookie_round_trip(self) -> None:
        engine = self.make_engine()
        request = make_request()
        cid, nonce = solve_challenge(engine, request)
        token = engine.validate_challenge(cid, nonce, request)
        assert token is not None
        assert engine.check_cookie(token, request)

    def test_cookie_wrong_ip(self) -> None:
        engine = self.make_engine()
        request = make_request(remote_addr="1.2.3.4")
        cid, nonce = solve_challenge(engine, request)
        token = engine.validate_challenge(cid, nonce, request)
        assert token is not None
        other = make_request(remote_addr="9.9.9.9")
        assert not engine.check_cookie(token, other)

    def test_cookie_invalid_token(self) -> None:
        engine = self.make_engine()
        assert not engine.check_cookie("garbage", make_request())

    def test_cookie_expired(self) -> None:
        engine = self.make_engine(cookie_ttl=-1)
        request = make_request()
        cid, nonce = solve_challenge(engine, request)
        token = engine.validate_challenge(cid, nonce, request)
        assert token is not None
        assert not engine.check_cookie(token, request)

    def test_process_with_valid_cookie(self) -> None:
        engine = self.make_engine(
            policy=Policy(
                rules=[
                    Rule(
                        name="all",
                        action="challenge",
                        difficulty=1,
                    ),
                ]
            )
        )
        request = make_request()
        cid, nonce = solve_challenge(engine, request)
        token = engine.validate_challenge(cid, nonce, request)
        assert token is not None
        request = make_request(cookies={COOKIE_NAME: token})
        action, _, _, _ = engine.process(request)
        assert action == "pass"

    def test_handle_verify_success(self) -> None:
        engine = self.make_engine()
        request = make_request()
        cid, nonce = solve_challenge(engine, request)
        request = make_request(
            form={
                "id": cid,
                "nonce": nonce,
                "redirect": "/dashboard",
            }
        )
        status, headers, _ = engine.handle_verify(request)
        assert status == 302
        assert headers["Location"] == "/dashboard"
        assert COOKIE_NAME in headers["Set-Cookie"]

    def test_handle_verify_failure(self) -> None:
        engine = self.make_engine()
        request = make_request(
            form={
                "id": "fake",
                "nonce": "0",
            }
        )
        status, _, body = engine.handle_verify(request)
        assert status == 403
        assert body == "Invalid"

    def test_handle_verify_redirect_sanitization(
        self,
    ) -> None:
        engine = self.make_engine()
        request = make_request()
        cid, nonce = solve_challenge(engine, request)
        for bad_redirect in [
            "//evil.com",
            "https://evil.com",
            "javascript:alert(1)",
        ]:
            stored = engine.store.get(cid)
            assert stored is not None
            stored.spent = False
            request = make_request(
                form={
                    "id": cid,
                    "nonce": nonce,
                    "redirect": bad_redirect,
                }
            )
            _, headers, _ = engine.handle_verify(request)
            assert headers["Location"] == "/"

    def test_balloon_leading_zero_bits(self) -> None:
        assert _count_leading_zero_bits(b"\x00\x0f") == 12
        assert _count_leading_zero_bits(b"\x00\x00") == 16
        assert _count_leading_zero_bits(b"\x80") == 0
        assert _count_leading_zero_bits(b"\x40") == 1
        assert _count_leading_zero_bits(b"\x01") == 7

    def test_render_challenge_contains_data(
        self,
    ) -> None:
        engine = self.make_engine()
        challenge = engine.issue_challenge(4, make_request())
        html = engine.render_challenge(challenge, "/")
        assert challenge.id in html
        assert challenge.random_data in html
        assert '"difficulty": 4' in html
