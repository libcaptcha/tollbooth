import json

from starlette.requests import Request

from .base import resolve_base
from .starlette import (
    TollboothMiddleware as _StarletteMiddleware,
    _parse_scope,
)


class TollboothMiddleware(_StarletteMiddleware):
    def __init__(self, app, secret, **kwargs):
        kwargs.setdefault("json_mode", True)
        super().__init__(app, secret, **kwargs)


class TollboothDep:
    def __init__(self, tb_or_secret, **kwargs):
        kwargs.setdefault("json_mode", True)
        self._tb = resolve_base(tb_or_secret, kwargs)

    async def __call__(self, request: Request):
        from fastapi import HTTPException

        req = _parse_scope(request.scope)
        result = self._tb.process_request(req)
        if not result:
            return

        try:
            detail = json.loads(result.body)
        except (json.JSONDecodeError, TypeError):
            detail = result.body

        raise HTTPException(
            status_code=result.status,
            detail=detail,
        )


def mount_verify(app, tb_or_secret, **kwargs):
    tb = resolve_base(tb_or_secret, kwargs)

    @app.post(tb.verify_path)
    async def verify(request: Request):
        from fastapi.responses import JSONResponse

        req = _parse_scope(request.scope)
        form = await request.form()
        req["form"] = dict(form)
        result = tb.process_request(req)
        if not result:
            return JSONResponse({"ok": True})
        return JSONResponse(
            json.loads(result.body),
            status_code=result.status,
        )
