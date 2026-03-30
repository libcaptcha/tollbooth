import asyncio
import functools
import time
from collections import OrderedDict
from threading import Lock

_UNITS = {
    "second": 1,
    "seconds": 1,
    "sec": 1,
    "minute": 60,
    "minutes": 60,
    "min": 60,
    "hour": 3600,
    "hours": 3600,
    "hr": 3600,
    "day": 86400,
    "days": 86400,
}

_RETRY_AFTER = "60"


def _parse_rate(rate: str) -> tuple[int, int]:
    rate = rate.strip().lower()
    for sep in (" per ", "/"):
        if sep in rate:
            count_str, unit = rate.split(sep, 1)
            window = _UNITS.get(unit.strip())
            if window:
                return int(count_str.strip()), window
    raise ValueError(f"Invalid rate: {rate!r}")


def _xff_or(xff: str, fallback: str) -> str:
    first = xff.split(",")[0].strip()
    return first if first else fallback


def _remote_ip(args: tuple, kwargs: dict) -> str:
    for obj in (*args, *kwargs.values()):
        if hasattr(obj, "META"):
            xff = obj.META.get("HTTP_X_FORWARDED_FOR", "")
            return _xff_or(xff, obj.META.get("REMOTE_ADDR", ""))

        if hasattr(obj, "remote_addr") and hasattr(obj, "get_header"):
            xff = obj.get_header("X-Forwarded-For") or ""
            return _xff_or(xff, obj.remote_addr or "")

        if hasattr(obj, "client") and hasattr(obj, "headers"):
            xff = obj.headers.get("x-forwarded-for", "")
            return _xff_or(xff, obj.client.host if obj.client else "")

    try:
        from flask import request as r

        xff = r.headers.get("X-Forwarded-For", "")
        return _xff_or(xff, r.remote_addr or "")
    except RuntimeError:
        return ""


def _reject_sync(args: tuple, kwargs: dict):
    for obj in (*args, *kwargs.values()):
        if hasattr(obj, "META"):
            from django.http import HttpResponse

            resp = HttpResponse(b"Too Many Requests", status=429)
            resp["Retry-After"] = _RETRY_AFTER
            return resp

        if hasattr(obj, "remote_addr") and hasattr(obj, "get_header"):
            import falcon

            raise falcon.HTTPTooManyRequests()

    try:
        from flask import Response

        return Response(
            "Too Many Requests",
            status=429,
            headers={"Retry-After": _RETRY_AFTER},
        )
    except (ImportError, RuntimeError):
        return None


async def _reject_async(args: tuple, kwargs: dict):
    for obj in (*args, *kwargs.values()):
        if hasattr(obj, "client") and hasattr(obj, "headers"):
            try:
                from starlette.exceptions import HTTPException

                raise HTTPException(
                    status_code=429,
                    detail="Too Many Requests",
                    headers={"Retry-After": _RETRY_AFTER},
                )
            except ImportError:
                pass

            try:
                from starlette.responses import Response

                return Response(
                    "Too Many Requests",
                    status_code=429,
                    headers={"Retry-After": _RETRY_AFTER},
                )
            except ImportError:
                pass

    return None


class _MemoryStore:
    def __init__(self, max_size: int = 10_000):
        self._data: OrderedDict[str, list[float]] = OrderedDict()
        self._max_size = max_size
        self._lock = Lock()

    def hit(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        cutoff = now - window

        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                hits = [t for t in self._data[key] if t > cutoff]
            else:
                hits = []
                if len(self._data) >= self._max_size:
                    self._data.popitem(last=False)

            if len(hits) >= limit:
                self._data[key] = hits
                return False

            hits.append(now)
            self._data[key] = hits
            return True


class _RedisStore:
    def __init__(self, client, prefix: str = "tbrl"):
        from ..redis import RedisRateLimiter

        self._limiter = RedisRateLimiter(client, prefix)

    def hit(self, key: str, limit: int, window: int) -> bool:
        return self._limiter.hit(key, limit, window)


class RateLimiter:
    """Standalone rate limiter with per-route decorators and multi-framework support.

    Backends: in-memory LRU (default) or Redis via ``redis_client``.

    Usage — decorator::

        rl = RateLimiter(default="100/minute")

        @rl.limit("10/minute")
        def my_view(request): ...

        @rl.exempt
        def health(request): ...

    Usage — Flask global::

        rl.init_flask(app, rate="200/minute")

    Usage — Django middleware::

        MIDDLEWARE = [
            "myapp.middleware.RateLimit",  # rl.as_django_middleware()
            ...
        ]

    Usage — WSGI/ASGI wrap::

        app = rl.wsgi_middleware(app)
        app = rl.asgi_middleware(app)

    Usage — FastAPI/Starlette dependency::

        @app.get("/")
        async def route(_=Depends(rl.fastapi_dependency("10/minute"))):
            ...
    """

    def __init__(
        self,
        default: str = "100/minute",
        max_size: int = 10_000,
        redis_client=None,
        prefix: str = "tbrl",
    ):
        self._default = _parse_rate(default)
        self._store = (
            _RedisStore(redis_client, prefix)
            if redis_client
            else _MemoryStore(max_size)
        )

    def limit(self, rate: str):
        lim, win = _parse_rate(rate)

        def decorator(func):
            if getattr(func, "_rl_exempt", False):
                return func

            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                ip = _remote_ip(args, kwargs)
                if not self._store.hit(f"{func.__qualname__}:{ip}", lim, win):
                    return _reject_sync(args, kwargs)
                return func(*args, **kwargs)

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                ip = _remote_ip(args, kwargs)
                if not self._store.hit(f"{func.__qualname__}:{ip}", lim, win):
                    result = await _reject_async(args, kwargs)
                    if result is not None:
                        return result
                return await func(*args, **kwargs)

            wrapper = (
                async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
            )
            setattr(wrapper, "_rl_limit", (lim, win))
            return wrapper

        return decorator

    def exempt(self, func):
        func._rl_exempt = True
        return func

    def init_flask(self, app, rate: str | None = None):
        lim, win = _parse_rate(rate) if rate else self._default
        store = self._store

        @app.before_request
        def _check():
            from flask import Response, request

            view = app.view_functions.get(request.endpoint)
            if view and getattr(view, "_rl_exempt", False):
                return None

            xff = request.headers.get("X-Forwarded-For", "")
            ip = _xff_or(xff, request.remote_addr or "")

            if not store.hit(f"{request.endpoint}:{ip}", lim, win):
                return Response(
                    "Too Many Requests",
                    status=429,
                    headers={"Retry-After": _RETRY_AFTER},
                )
            return None

    def as_django_middleware(self, rate: str | None = None):
        lim, win = _parse_rate(rate) if rate else self._default
        store = self._store

        class RateLimitMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response

            def __call__(self, request):
                return self.get_response(request)

            def process_view(self, request, view_func, view_args, view_kwargs):
                if getattr(view_func, "_rl_exempt", False):
                    return None

                xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
                ip = _xff_or(xff, request.META.get("REMOTE_ADDR", ""))

                if not store.hit(f"{view_func.__name__}:{ip}", lim, win):
                    from django.http import HttpResponse

                    resp = HttpResponse(b"Too Many Requests", status=429)
                    resp["Retry-After"] = _RETRY_AFTER
                    return resp

                return None

        return RateLimitMiddleware

    def wsgi_middleware(self, app, rate: str | None = None):
        lim, win = _parse_rate(rate) if rate else self._default
        store = self._store

        def middleware(environ, start_response):
            xff = environ.get("HTTP_X_FORWARDED_FOR", "")
            ip = _xff_or(xff, environ.get("REMOTE_ADDR", ""))
            path = environ.get("PATH_INFO", "/")

            if not store.hit(f"{path}:{ip}", lim, win):
                start_response(
                    "429 Too Many Requests",
                    [
                        ("Content-Type", "text/plain"),
                        ("Retry-After", _RETRY_AFTER),
                    ],
                )
                return [b"Too Many Requests"]

            return app(environ, start_response)

        return middleware

    def asgi_middleware(self, app, rate: str | None = None):
        lim, win = _parse_rate(rate) if rate else self._default
        store = self._store

        async def middleware(scope, receive, send):
            if scope["type"] != "http":
                await app(scope, receive, send)
                return

            raw = dict(scope.get("headers", []))
            xff = raw.get(b"x-forwarded-for", b"").decode()
            client = scope.get("client")
            ip = _xff_or(xff, client[0] if client else "")
            path = scope.get("path", "/")

            if not store.hit(f"{path}:{ip}", lim, win):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 429,
                        "headers": [
                            [b"content-type", b"text/plain"],
                            [b"retry-after", _RETRY_AFTER.encode()],
                        ],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b"Too Many Requests",
                    }
                )
                return

            await app(scope, receive, send)

        return middleware

    def fastapi_dependency(self, rate: str | None = None):
        lim, win = _parse_rate(rate) if rate else self._default
        store = self._store

        async def _dep(request):
            xff = request.headers.get("x-forwarded-for", "")
            ip = _xff_or(xff, request.client.host if request.client else "")

            if not store.hit(f"{request.url.path}:{ip}", lim, win):
                try:
                    from starlette.exceptions import HTTPException
                except ImportError:
                    from fastapi.exceptions import HTTPException
                raise HTTPException(
                    status_code=429,
                    detail="Too Many Requests",
                    headers={"Retry-After": _RETRY_AFTER},
                )

        try:
            from starlette.requests import Request

            _dep.__annotations__["request"] = Request
        except ImportError:
            pass

        return _dep
