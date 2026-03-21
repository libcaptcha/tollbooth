"""
Usage:
  WSGI:  python example.py wsgi
  ASGI:  python example.py asgi

Then visit http://localhost:8000 in a browser.
Try with curl to trigger a challenge:
  curl -v http://localhost:8000/
"""

import sys
from collections.abc import Iterable
from typing import Any

from tollbooth import TollboothWSGI, TollboothASGI, Policy, Rule

SECRET = "change-me-to-a-real-32-byte-key!"

POLICY = Policy(rules=[Rule(name="everyone", action="challenge")])


def app(
    _environ: dict[str, Any],
    start_response: Any,
) -> Iterable[bytes]:
    start_response(
        "200 OK",
        [("Content-Type", "text/plain")],
    )
    return [b"Hello from upstream!"]


async def asgi_app(
    scope: dict[str, Any],
    _receive: Any,
    send: Any,
) -> None:
    if scope["type"] != "http":
        return
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"text/plain"],
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": b"Hello from upstream!",
        }
    )


def run_wsgi() -> None:
    from wsgiref.simple_server import make_server

    wrapped = TollboothWSGI(app, secret=SECRET, policy=POLICY)
    server = make_server("0.0.0.0", 8000, wrapped)
    print("WSGI server on http://localhost:8000")
    server.serve_forever()


def run_asgi() -> None:
    import asyncio

    wrapped = TollboothASGI(asgi_app, secret=SECRET, policy=POLICY)

    async def serve() -> None:
        try:
            import uvicorn

            config = uvicorn.Config(wrapped, host="0.0.0.0", port=8000)
            server = uvicorn.Server(config)
            await server.serve()
        except ImportError:
            print("pip install uvicorn for ASGI")

    asyncio.run(serve())


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "wsgi"
    run_asgi() if mode == "asgi" else run_wsgi()
