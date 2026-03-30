import flask

from tollbooth import Rule
from tollbooth.integrations.flask import Tollbooth, tollbooth_protect

SECRET = "change-me-to-a-real-32-byte-key!"
RULES = [Rule(name="everyone", action="challenge")]

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = SECRET

tb = Tollbooth(app, rules=RULES)
tb.mount_verify(app)


@app.route("/")
def index():
    return f"Hello! Claims: {flask.g.get('tollbooth')}"


@app.route("/open")
@tb.exempt
def open_route():
    return "No challenge here"


@app.route("/protected")
@tollbooth_protect(SECRET, rules=RULES)
def protected():
    return "Per-route protection"


if __name__ == "__main__":
    app.run(port=8000)
