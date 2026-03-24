from functools import wraps
from typing import Unpack

from django.http import HttpResponse
from django.urls import Resolver404, resolve

from .base import TollboothBase, TollboothKwargs, resolve_base


def _to_request(r):
    forwarded = r.META.get(
        "HTTP_X_FORWARDED_FOR",
        "",
    )
    remote = r.META.get("REMOTE_ADDR", "")
    return {
        "method": r.method,
        "path": r.path,
        "query": r.META.get("QUERY_STRING", ""),
        "user_agent": r.META.get(
            "HTTP_USER_AGENT",
            "",
        ),
        "remote_addr": (forwarded.split(",")[0].strip() if forwarded else remote),
        "headers": {
            k[5:].replace("_", "-").title(): v
            for k, v in r.META.items()
            if k.startswith("HTTP_")
        },
        "cookies": dict(r.COOKIES),
        "form": {k: v for k, v in r.POST.items()},
    }


def _to_response(result):
    resp = HttpResponse(
        result.body,
        status=result.status,
    )
    for k, v in result.headers.items():
        resp[k] = v
    return resp


class TollboothMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        from django.conf import settings

        kwargs = dict(getattr(settings, "TOLLBOOTH", {}))
        if "secret" not in kwargs and "engine" not in kwargs:
            kwargs.setdefault(
                "secret",
                getattr(settings, "SECRET_KEY", None),
            )
        self._tb = TollboothBase(**kwargs)

    def __call__(self, request):
        try:
            match = resolve(request.path_info)
            if getattr(
                match.func,
                "_tollbooth_exempt",
                False,
            ):
                return self.get_response(request)
        except Resolver404:
            pass

        req = _to_request(request)
        result = self._tb.process_request(req)
        if result:
            return _to_response(result)
        return self.get_response(request)


def make_middleware(secret, **kwargs: Unpack[TollboothKwargs]):
    tb = TollboothBase(secret=secret, **kwargs)

    class _Middleware:
        def __init__(self, get_response):
            self.get_response = get_response

        def __call__(self, request):
            req = _to_request(request)
            result = tb.process_request(req)
            if result:
                return _to_response(result)
            return self.get_response(request)

    return _Middleware


def make_verify_view(tb_or_secret, **kwargs: Unpack[TollboothKwargs]):
    tb = resolve_base(tb_or_secret, kwargs)

    def view(request):
        req = _to_request(request)
        result = tb.process_request(req)
        if result:
            return _to_response(result)
        return HttpResponse(status=200)

    return view


def tollbooth_exempt(view):
    view._tollbooth_exempt = True
    return view


def tollbooth_protect(tb_or_secret, **kwargs: Unpack[TollboothKwargs]):
    tb = resolve_base(tb_or_secret, kwargs)

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kw):
            req = _to_request(request)
            result = tb.process_request(req)
            if result:
                return _to_response(result)
            return view(request, *args, **kw)

        return wrapper

    return decorator
