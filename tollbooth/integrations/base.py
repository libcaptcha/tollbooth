import json
import re
from dataclasses import dataclass

from ..engine import Engine, _CHALLENGE_HEADERS

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
        secret,
        *,
        exclude: list[str] | None = None,
        json_mode: bool = False,
        **engine_kwargs,
    ):
        self.engine = Engine(
            secret=secret,
            **engine_kwargs,
        )
        self._excludes = [re.compile(p) for p in (exclude or [])]
        self.json_mode = json_mode

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

        action, difficulty = self.engine.policy.evaluate(request)

        if action == "allow":
            return None
        if action == "deny":
            return self._deny()

        return self._challenge(difficulty, request)

    def _deny(self):
        if self.json_mode:
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

    def _challenge(self, difficulty, request):
        challenge = self.engine.issue_challenge(
            difficulty,
            request,
        )
        path = request["path"]

        if self.json_mode:
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

        if self.json_mode:
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

        redirect = form.get("redirect", "/")
        if (
            not redirect.startswith("/")
            or redirect.startswith("//")
            or redirect.startswith("/\\")
            or "\n" in redirect
            or "\r" in redirect
        ):
            redirect = "/"

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
