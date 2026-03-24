import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import TypedDict, Unpack

from .challenges import ChallengeBase, ChallengeHandler, SHA256Balloon

Challenge = ChallengeBase

COOKIE_NAME = "_tollbooth"
VERIFY_PATH = "/.tollbooth/verify"
CHALLENGE_TTL = 1800
COOKIE_TTL = 604800
CHALLENGE_THRESHOLD = 5
MAX_STORE_SIZE = 100_000
DEFAULT_DIFFICULTY = 10


class Request(TypedDict):
    method: str
    path: str
    query: str
    user_agent: str
    remote_addr: str
    headers: dict[str, str]
    cookies: dict[str, str]
    form: dict[str, str]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))


_JWT_HEADER = _b64url_encode(b'{"alg":"HS256","typ":"JWT"}')


def jwt_encode(claims: dict, secret: bytes) -> str:
    payload = _b64url_encode(json.dumps(claims).encode())
    signing = f"{_JWT_HEADER}.{payload}"
    sig = hmac.new(secret, signing.encode(), hashlib.sha256).digest()

    return f"{signing}.{_b64url_encode(sig)}"


def jwt_decode(token: str, secret: bytes) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid token")

    if parts[0] != _JWT_HEADER:
        raise ValueError("unsupported algorithm")

    signing = f"{parts[0]}.{parts[1]}"
    expected = hmac.new(
        secret,
        signing.encode(),
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(expected, _b64url_decode(parts[2])):
        raise ValueError("invalid signature")

    claims = json.loads(_b64url_decode(parts[1]))
    if claims.get("exp", 0) < time.time():
        raise ValueError("token expired")

    return claims


class Store:
    def __init__(
        self,
        challenge_ttl: int = CHALLENGE_TTL,
        max_size: int = MAX_STORE_SIZE,
    ):
        self._ttl = challenge_ttl
        self._max_size = max_size
        self._data: dict[str, ChallengeBase] = {}
        self._lock = Lock()

    def _cleanup(self):
        cutoff = time.time() - self._ttl
        for k in [k for k, v in self._data.items() if v.created_at < cutoff]:
            del self._data[k]

    def _evict_oldest(self):
        excess = len(self._data) - self._max_size + 1
        if excess <= 0:
            return
        oldest = sorted(
            self._data,
            key=lambda k: self._data[k].created_at,
        )[:excess]
        for k in oldest:
            del self._data[k]

    def set(self, challenge: ChallengeBase):
        with self._lock:
            self._cleanup()
            self._evict_oldest()
            self._data[challenge.id] = challenge

    def get(self, cid: str) -> ChallengeBase | None:
        with self._lock:
            self._cleanup()
            return self._data.get(cid)


class RateLimiter:
    def __init__(self):
        self._data: dict[str, list[float]] = {}
        self._lock = Lock()

    def hit(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        cutoff = now - window
        with self._lock:
            hits = [t for t in self._data.get(key, []) if t > cutoff]
            if len(hits) >= limit:
                self._data[key] = hits
                return False
            hits.append(now)
            self._data[key] = hits
            return True


@dataclass
class Rule:
    name: str
    action: str = "weigh"
    user_agent: str | None = None
    path: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    remote_addresses: list[str] = field(default_factory=list)
    difficulty: int = 0
    weight: int = 0
    blocklist: bool = False

    def __post_init__(self):
        self.action = self.action.lower()

        self._ua_re = re.compile(self.user_agent) if self.user_agent else None
        self._path_re = re.compile(self.path) if self.path else None
        self._header_res = {k: re.compile(v) for k, v in self.headers.items()}
        self._networks = [
            ipaddress.ip_network(a, strict=False) for a in self.remote_addresses
        ]

    def matches(self, request: Request, blocklist=None) -> bool:
        if self.blocklist and (
            not blocklist or not blocklist.contains(request["remote_addr"])
        ):
            return False

        if self._ua_re and not self._ua_re.search(request["user_agent"]):
            return False

        if self._path_re and not self._path_re.search(request["path"]):
            return False

        if any(
            not p.search(request["headers"].get(k, ""))
            for k, p in self._header_res.items()
        ):
            return False

        if not self._networks:
            return True

        try:
            addr = ipaddress.ip_address(request["remote_addr"])
        except ValueError:
            return False

        return any(addr in n for n in self._networks)


@dataclass
class Policy:
    rules: list[Rule]
    challenge_threshold: int = CHALLENGE_THRESHOLD
    default_difficulty: int = DEFAULT_DIFFICULTY
    challenge_handler: ChallengeHandler = field(default_factory=SHA256Balloon)
    cookie_name: str = COOKIE_NAME
    verify_path: str = VERIFY_PATH
    challenge_ttl: int = CHALLENGE_TTL
    cookie_ttl: int = COOKIE_TTL
    branding: bool = True
    accent_color: str = "#44ff88"
    max_challenge_failures: int = 3
    max_challenge_requests: int = 10
    rate_limit_window: int = 300

    def evaluate(
        self,
        request: Request,
        blocklist=None,
    ) -> tuple[str, int]:
        weight = 0

        for rule in self.rules:
            if not rule.matches(request, blocklist):
                continue
            if rule.action in ("allow", "deny"):
                return rule.action, 0
            if rule.action == "challenge":
                return (
                    "challenge",
                    rule.difficulty or self.default_difficulty,
                )
            weight += rule.weight

        if weight >= self.challenge_threshold:
            return "challenge", self.default_difficulty

        return "allow", 0


def load_policy(config=None, rules=None) -> Policy:
    base = Path(__file__).parent

    cfg_path = Path(config) if config else (base / "config.json")
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}

    rules_path = Path(rules) if rules else base / "rules.json"
    rule_list = json.loads(rules_path.read_text())

    return Policy(
        rules=[Rule(**r) for r in rule_list],
        **cfg,
    )


def _safe_redirect(redirect: str) -> str:
    if (
        not redirect.startswith("/")
        or redirect.startswith("//")
        or redirect.startswith("/\\")
        or "\n" in redirect
        or "\r" in redirect
    ):
        return "/"
    return redirect


_CSP = (
    "default-src 'none'; "
    "script-src 'unsafe-inline'; "
    "worker-src blob:; "
    "style-src 'unsafe-inline'; "
    "img-src data:; "
    "connect-src 'self'"
)

_CHALLENGE_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": _CSP,
}


class EngineKwargs(TypedDict, total=False):
    config_file: str | None
    rules_file: str | None
    blocklist: object
    challenge_threshold: int
    default_difficulty: int
    challenge_handler: ChallengeHandler
    cookie_name: str
    verify_path: str
    challenge_ttl: int
    cookie_ttl: int
    branding: bool
    accent_color: str
    max_challenge_failures: int
    max_challenge_requests: int
    rate_limit_window: int


class Engine:
    def __init__(self, secret, policy=None, **kwargs: Unpack[EngineKwargs]):
        config_file = kwargs.pop("config_file", None)
        rules_file = kwargs.pop("rules_file", None)
        self.blocklist = kwargs.pop("blocklist", None)

        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.policy = policy or load_policy(config_file, rules_file)

        for key, val in kwargs.items():
            setattr(self.policy, key, val)

        handler = self.policy.challenge_handler
        if hasattr(handler, "secret"):
            setattr(handler, "secret", self.secret)

        self.store = Store(self.policy.challenge_ttl)
        self._rate_limiter = RateLimiter()

    def _hmac(self, data: bytes) -> bytes:
        return hmac.new(self.secret, data, hashlib.sha256).digest()

    def _hash_ip(self, ip: str) -> str:
        return self._hmac(ip.encode()).hex()[:16]

    def check_cookie(
        self,
        cookie_value: str,
        request: Request,
    ) -> bool:
        try:
            claims = jwt_decode(cookie_value, self.secret)
            return hmac.compare_digest(
                str(claims.get("ip", "")),
                self._hash_ip(request["remote_addr"]),
            )
        except (ValueError, KeyError):
            return False

    def issue_challenge(
        self,
        difficulty: int,
        request: Request,
    ) -> ChallengeBase:
        handler = self.policy.challenge_handler
        effective = handler.to_difficulty(difficulty)
        challenge = ChallengeBase(
            id=secrets.token_urlsafe(24),
            random_data=handler.generate_random_data(effective),
            difficulty=effective,
            ip_hash=self._hash_ip(request["remote_addr"]),
            created_at=time.time(),
            challenge_type=handler.challenge_type,
        )
        self.store.set(challenge)
        return challenge

    def validate_challenge(
        self,
        challenge_id,
        nonce,
        request,
    ) -> str | None:
        challenge = self.store.get(challenge_id)
        if not challenge or challenge.spent:
            return None

        if challenge.challenge_type != self.policy.challenge_handler.challenge_type:
            return None

        if not hmac.compare_digest(
            challenge.ip_hash,
            self._hash_ip(request["remote_addr"]),
        ):
            return None

        try:
            nonce_val = self.policy.challenge_handler.nonce_from_form(str(nonce))
        except (ValueError, TypeError):
            return None

        if not self.policy.challenge_handler.verify(
            challenge.random_data, nonce_val, challenge.difficulty
        ):
            return None

        challenge.spent = True
        self.store.set(challenge)

        now = time.time()
        return jwt_encode(
            {
                "iat": int(now),
                "exp": int(now + self.policy.cookie_ttl),
                "ip": self._hash_ip(request["remote_addr"]),
                "cid": challenge_id,
            },
            self.secret,
        )

    _BRANDING = (
        '<div class="branding">'
        "Protected by "
        '<a href="https://github.com/libcaptcha/'
        'tollbooth">tollbooth</a>'
        " · "
        '<a href="https://github.com/libcaptcha">'
        "libcaptcha</a>"
        "</div>"
    )

    def render_challenge(
        self,
        challenge: ChallengeBase,
        redirect_to: str,
        error: str = "",
    ) -> str:
        handler = self.policy.challenge_handler
        payload_dict = handler.render_payload(
            challenge, self.policy.verify_path, redirect_to
        )
        payload = json.dumps(payload_dict)
        branding = self._BRANDING if self.policy.branding else ""

        safe = (
            payload.replace("'", "\\u0027")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )

        html = (
            handler.template.replace("{{CHALLENGE_DATA}}", safe)
            .replace("{{BRANDING}}", branding)
            .replace("{{ERROR}}", error)
            .replace("{{ACCENT_COLOR}}", self.policy.accent_color)
        )
        for key, value in payload_dict.items():
            html = html.replace(f"{{{{{key}}}}}", str(value))
        return html

    def process(
        self,
        request: Request,
    ) -> tuple[str, int, dict[str, str], str]:
        cookie = request["cookies"].get(
            self.policy.cookie_name,
        )
        if cookie and self.check_cookie(cookie, request):
            return "pass", 0, {}, ""

        action, difficulty = self.policy.evaluate(
            request,
            self.blocklist,
        )

        if action == "allow":
            return "pass", 0, {}, ""
        if action == "deny":
            return (
                "deny",
                403,
                {"Content-Type": "text/plain"},
                "Forbidden",
            )

        ip_hash = self._hash_ip(request["remote_addr"])
        if not self._rate_limiter.hit(
            f"gen:{ip_hash}",
            self.policy.max_challenge_requests,
            self.policy.rate_limit_window,
        ):
            return "deny", 403, {"Content-Type": "text/plain"}, "Too Many Requests"

        challenge = self.issue_challenge(difficulty, request)
        body = self.render_challenge(challenge, request["path"])
        return "challenge", 200, _CHALLENGE_HEADERS, body

    def handle_verify(
        self,
        request: Request,
    ) -> tuple[int, dict[str, str], str]:
        form = request["form"]
        token = self.validate_challenge(
            form.get("id", ""),
            form.get("nonce", ""),
            request,
        )

        if not token:
            ip_hash = self._hash_ip(request["remote_addr"])
            if not self._rate_limiter.hit(
                f"fail:{ip_hash}",
                self.policy.max_challenge_failures,
                self.policy.rate_limit_window,
            ):
                return 403, {"Content-Type": "text/plain"}, "Too Many Requests"

            if self.policy.challenge_handler.retry_on_failure:
                redirect = _safe_redirect(form.get("redirect", "/"))
                challenge = self.issue_challenge(
                    self.policy.default_difficulty, request
                )
                body = self.render_challenge(
                    challenge,
                    redirect,
                    error='<p class="error">Incorrect \u2014 try again.</p>',
                )
                return 200, _CHALLENGE_HEADERS, body
            return 403, {"Content-Type": "text/plain"}, "Invalid"

        redirect = _safe_redirect(form.get("redirect", "/"))

        cookie = (
            f"{self.policy.cookie_name}={token}; "
            f"Path=/; HttpOnly; SameSite=Strict; "
            f"Secure; Max-Age={self.policy.cookie_ttl}"
        )

        return (
            302,
            {
                "Location": redirect,
                "Set-Cookie": cookie,
            },
            "",
        )
