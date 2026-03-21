from functools import wraps

import flask

from .base import TollboothBase, resolve_base


def _to_request():
    r = flask.request
    forwarded = r.headers.get(
        "X-Forwarded-For",
        "",
    )
    return {
        "method": r.method,
        "path": r.path,
        "query": r.query_string.decode(),
        "user_agent": r.user_agent.string,
        "remote_addr": (
            forwarded.split(",")[0].strip() if forwarded else (r.remote_addr or "")
        ),
        "headers": dict(r.headers),
        "cookies": dict(r.cookies),
        "form": dict(r.form),
    }


def _to_response(result):
    return flask.Response(
        result.body,
        status=result.status,
        headers=result.headers,
    )


class Tollbooth:
    def __init__(self, app=None, **kwargs):
        self._kwargs = kwargs
        self._tb: TollboothBase | None = (
            TollboothBase(**kwargs) if "secret" in kwargs else None
        )
        if app:
            self.init_app(app)

    @property
    def tb(self) -> TollboothBase:
        assert self._tb, "Call init_app() first"
        return self._tb

    def init_app(self, app):
        if not self._tb:
            self._tb = TollboothBase(**self._kwargs)
        app.before_request(self._check)
        app.extensions["tollbooth"] = self

    def _check(self):
        endpoint = flask.request.endpoint
        view = flask.current_app.view_functions.get(endpoint) if endpoint else None
        if view and getattr(
            view,
            "_tollbooth_exempt",
            False,
        ):
            return None

        req = _to_request()
        result = self.tb.process_request(req)
        if result:
            return _to_response(result)
        return None

    def exempt(self, view):
        view._tollbooth_exempt = True
        return view

    def protect(self, view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            req = _to_request()
            result = self.tb.process_request(req)
            if result:
                return _to_response(result)
            return view(*args, **kwargs)

        return wrapper

    def mount_verify(self, app):
        @app.route(
            self.tb.verify_path,
            methods=["POST"],
        )
        def _verify():
            req = _to_request()
            result = self.tb.process_request(req)
            if result:
                return _to_response(result)
            return "", 200


def tollbooth_protect(tb_or_secret, **kwargs):
    tb = resolve_base(tb_or_secret, kwargs)

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kw):
            req = _to_request()
            result = tb.process_request(req)
            if result:
                return _to_response(result)
            return view(*args, **kw)

        return wrapper

    return decorator
