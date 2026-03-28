import json
import re
import types
from collections.abc import Callable
from dataclasses import dataclass
from typing import Unpack

from ..engine import (
    Engine,
    EngineKwargs,
    _blocklist_match,
    _challenge_headers,
    _safe_redirect,
)

try:
    import crawleruseragents as _cua
except ImportError:
    _cua = None


class TollboothKwargs(EngineKwargs, total=False):
    secret: str | None
    engine: Engine | None
    exclude: list[str] | None
    json_mode: bool | Callable[[dict], bool]


_JSON_CT = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
}


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str


def resolve_base(tb_or_secret, kwargs: TollboothKwargs):
    if isinstance(tb_or_secret, TollboothBase):
        return tb_or_secret
    return TollboothBase(
        secret=tb_or_secret,
        **kwargs,
    )


class TollboothBase:
    def __init__(
        self,
        secret=None,
        *,
        engine: Engine | None = None,
        exclude: list[str] | None = None,
        json_mode: bool | Callable[[dict], bool] = False,
        **engine_kwargs: Unpack[EngineKwargs],
    ):
        if engine:
            self.engine = engine
        elif secret:
            self.engine = Engine(
                secret=secret,
                **engine_kwargs,
            )
        else:
            raise ValueError("secret or engine required")
        self._excludes = [re.compile(p) for p in (exclude or [])]
        self._json_mode = json_mode

    def _is_json(self, request):
        if callable(self._json_mode):
            return self._json_mode(request)
        return self._json_mode

    @property
    def verify_path(self):
        return self.engine.policy.verify_path

    def is_excluded(self, path):
        return any(p.search(path) for p in self._excludes)

    def is_verify(self, method, path):
        return method == "POST" and path == self.verify_path

    def _crawler_fields(self, user_agent: str) -> tuple[bool, str | None]:
        if _cua is None:
            return False, None
        is_crawler = bool(_cua.is_crawler(user_agent))
        crawler_name = user_agent.split("/")[0].strip() if is_crawler else None
        return is_crawler, crawler_name

    def process_request(self, request):
        if self.is_excluded(request["path"]):
            return None

        if self.is_verify(
            request["method"],
            request["path"],
        ):
            cookie = request["cookies"].get(self.engine.policy.cookie_name)
            if cookie and self.engine.check_cookie(cookie, request):
                return self._deny(self._is_json(request))
            return self._handle_verify(request)

        cookie = request["cookies"].get(self.engine.policy.cookie_name)
        if cookie:
            claims = self.engine.check_cookie(cookie, request)
            if claims and self.engine.check_token_limit(claims["cid"]):
                is_crawler, crawler_name = self._crawler_fields(request["user_agent"])
                request["_claims"] = types.SimpleNamespace(
                    **{
                        "score": None,
                        "matched_rule": None,
                        "blocklist_match": None,
                        "is_crawler": is_crawler,
                        "crawler_name": crawler_name,
                        **claims,
                    }
                )
                return None

        action, difficulty, matched_rule = self.engine.policy.evaluate(
            request,
            self.engine.blocklist,
        )

        if action == "allow":
            is_crawler, crawler_name = self._crawler_fields(request["user_agent"])
            bl_match = (
                _blocklist_match(self.engine.blocklist, request["remote_addr"])
                if matched_rule and matched_rule.blocklist
                else None
            )
            request["_claims"] = types.SimpleNamespace(
                score=None,
                matched_rule=matched_rule.name if matched_rule else None,
                blocklist_match=bl_match,
                is_crawler=is_crawler,
                crawler_name=crawler_name,
            )
            return None

        use_json = self._is_json(request)

        if action == "deny":
            return self._deny(use_json)

        return self._challenge(difficulty, request, use_json)

    def _deny(self, use_json):
        if use_json:
            return Response(
                403,
                dict(_JSON_CT),
                '{"error":"forbidden"}',
            )
        return Response(
            403,
            {"Content-Type": "text/plain"},
            "Forbidden",
        )

    def _challenge(self, difficulty, request, use_json):
        ip_hash = self.engine._hash_ip(request["remote_addr"])
        if not self.engine._rate_limiter.hit(
            f"gen:{ip_hash}",
            self.engine.policy.max_challenge_requests,
            self.engine.policy.rate_limit_window,
        ):
            if use_json:
                return Response(403, dict(_JSON_CT), '{"error":"too many requests"}')
            return Response(403, {"Content-Type": "text/plain"}, "Too Many Requests")

        challenge = self.engine.issue_challenge(difficulty, request)
        path = request["path"]

        if use_json:
            handler = self.engine.policy.challenge_handler
            payload = handler.render_payload(challenge, self.verify_path, path)
            body = json.dumps({"challenge": payload})
            return Response(200, dict(_JSON_CT), body)

        body = self.engine.render_challenge(challenge, path)
        return Response(
            200, _challenge_headers(self.engine.policy.challenge_handler), body
        )

    def _handle_verify(self, request):
        form = request["form"]
        nonce = form.get("nonce") or ",".join(
            filter(None, [form.get("nonce.x", ""), form.get("nonce.y", "")])
        )
        token = self.engine.validate_challenge(form.get("id", ""), nonce, request)
        use_json = self._is_json(request)

        if not token:
            ip_hash = self.engine._hash_ip(request["remote_addr"])
            if not self.engine._rate_limiter.hit(
                f"fail:{ip_hash}",
                self.engine.policy.max_challenge_failures,
                self.engine.policy.rate_limit_window,
            ):
                if use_json:
                    return Response(
                        403, dict(_JSON_CT), '{"error":"too many requests"}'
                    )
                return Response(
                    403, {"Content-Type": "text/plain"}, "Too Many Requests"
                )

            if use_json:
                return Response(403, dict(_JSON_CT), '{"error":"invalid"}')
            if self.engine.policy.challenge_handler.retry_on_failure:
                redirect = _safe_redirect(form.get("redirect", "/"))
                challenge = self.engine.issue_challenge(
                    self.engine.policy.default_difficulty, request
                )
                body = self.engine.render_challenge(
                    challenge,
                    redirect,
                    error='<p class="error">Incorrect \u2014 try again.</p>',
                )
                return Response(
                    429, _challenge_headers(self.engine.policy.challenge_handler), body
                )
            return Response(403, {"Content-Type": "text/plain"}, "Invalid")

        if use_json:
            return Response(
                200,
                dict(_JSON_CT),
                json.dumps({"token": token}),
            )

        redirect = _safe_redirect(
            form.get("redirect", "/"),
        )
        p = self.engine.policy
        cookie_val = (
            f"{p.cookie_name}={token}; "
            f"Path=/; HttpOnly; SameSite=Strict; "
            f"Secure; Max-Age={p.cookie_ttl}"
        )
        return Response(
            302,
            {
                "Location": redirect,
                "Set-Cookie": cookie_val,
            },
            "",
        )
