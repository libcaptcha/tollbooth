import json
import re
from collections.abc import Callable
from dataclasses import dataclass

from ..engine import _CHALLENGE_HEADERS, Engine, _safe_redirect

_JSON_CT = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
}


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str


def resolve_base(tb_or_secret, kwargs):
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
        **engine_kwargs,
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

    def process_request(self, request):
        if self.is_excluded(request["path"]):
            return None

        if self.is_verify(
            request["method"],
            request["path"],
        ):
            return self._handle_verify(request)

        cookie = request["cookies"].get(
            self.engine.policy.cookie_name,
        )
        if cookie and self.engine.check_cookie(
            cookie,
            request,
        ):
            return None

        action, difficulty = self.engine.policy.evaluate(
            request,
            self.engine.blocklist,
        )

        if action == "allow":
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
        challenge = self.engine.issue_challenge(
            difficulty,
            request,
        )
        path = request["path"]

        if use_json:
            p = self.engine.policy
            body = json.dumps(
                {
                    "challenge": {
                        "id": challenge.id,
                        "data": challenge.random_data,
                        "difficulty": challenge.difficulty,
                        "space_cost": p.space_cost,
                        "time_cost": p.time_cost,
                        "delta": p.delta,
                        "verify_path": self.verify_path,
                        "redirect": path,
                    }
                }
            )
            return Response(429, dict(_JSON_CT), body)

        body = self.engine.render_challenge(
            challenge,
            path,
        )
        return Response(
            429,
            dict(_CHALLENGE_HEADERS),
            body,
        )

    def _handle_verify(self, request):
        form = request["form"]
        token = self.engine.validate_challenge(
            form.get("id", ""),
            form.get("nonce", ""),
            request,
        )
        use_json = self._is_json(request)

        if use_json:
            if not token:
                return Response(
                    403,
                    dict(_JSON_CT),
                    '{"error":"invalid"}',
                )
            return Response(
                200,
                dict(_JSON_CT),
                json.dumps({"token": token}),
            )

        if not token:
            return Response(
                403,
                {"Content-Type": "text/plain"},
                "Invalid",
            )

        redirect = _safe_redirect(form.get("redirect", "/"))

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
