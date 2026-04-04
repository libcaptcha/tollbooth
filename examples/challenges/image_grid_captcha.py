"""Image grid CAPTCHA (3x3 grid, select matching). Requires: pip install tollbooth[image]"""

from collections.abc import Iterable
from typing import Any
from wsgiref.simple_server import make_server

from tollbooth import ImageGridCaptcha, Rule, TollboothWSGI

SECRET = "change-me-to-a-real-32-byte-key!"
RULES = [Rule(name="everyone", action="challenge")]


def app(_environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"Hello from upstream!"]


if __name__ == "__main__":
    handler = ImageGridCaptcha(secret=SECRET.encode())
    wrapped = TollboothWSGI(app, SECRET, rules=RULES, challenge_handler=handler)
    print("ImageGridCaptcha challenge on http://localhost:8000")
    make_server("0.0.0.0", 8000, wrapped).serve_forever()
