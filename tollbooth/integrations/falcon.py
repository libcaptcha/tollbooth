from urllib.parse import parse_qs

from .base import TollboothBase, resolve_base


def _to_request(req):
    forwarded = req.get_header("X-Forwarded-For") or ""
    return {
        "method": req.method,
        "path": req.path,
        "query": req.query_string or "",
        "user_agent": req.user_agent or "",
        "remote_addr": (
            forwarded.split(",")[0].strip() if forwarded else (req.remote_addr or "")
        ),
        "headers": {k.title(): v for k, v in req.headers.items()},
        "cookies": dict(req.cookies),
        "form": {},
    }


def _read_form(req):
    try:
        length = min(
            int(req.get_header("Content-Length") or 0),
            1_048_576,
        )
        body = req.bounded_stream.read(length)
        return {
            k: v[0]
            for k, v in parse_qs(
                body.decode(),
            ).items()
        }
    except (ValueError, UnicodeDecodeError):
        return {}


def _set_cookie(resp, raw):
    parts = [p.strip() for p in raw.split(";")]
    name, value = parts[0].split("=", 1)
    kwargs = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            key = k.strip().lower().replace("-", "_")
            if key == "max_age":
                kwargs["max_age"] = int(v)
            elif key == "path":
                kwargs["path"] = v
            elif key == "same_site":
                kwargs["same_site"] = v
        else:
            flag = part.strip().lower()
            if flag == "httponly":
                kwargs["http_only"] = True
            elif flag == "secure":
                kwargs["secure"] = True
    resp.set_cookie(name, value, **kwargs)


def _apply(result, resp):
    resp.status = result.status
    resp.text = result.body
    for k, v in result.headers.items():
        if k == "Set-Cookie":
            _set_cookie(resp, v)
        else:
            resp.set_header(k, v)
    resp.complete = True


class TollboothMiddleware:
    def __init__(self, secret, **kwargs):
        self._tb = TollboothBase(
            secret=secret,
            **kwargs,
        )

    def process_request(self, req, resp):
        request = _to_request(req)

        if self._tb.is_verify(req.method, req.path):
            request["form"] = _read_form(req)

        result = self._tb.process_request(request)
        if result:
            _apply(result, resp)


class VerifyResource:
    def __init__(self, tb_or_secret, **kwargs):
        self._tb = resolve_base(tb_or_secret, kwargs)

    def on_post(self, req, resp):
        request = _to_request(req)
        request["form"] = _read_form(req)
        result = self._tb.process_request(request)
        if result:
            _apply(result, resp)


def tollbooth_hook(tb_or_secret, **kwargs):
    tb = resolve_base(tb_or_secret, kwargs)

    def hook(req, resp, resource, params):
        request = _to_request(req)
        result = tb.process_request(request)
        if result:
            _apply(result, resp)

    return hook
