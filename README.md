<div align="center">

# tollbooth

Proof-of-work bot challenge middleware for Python. Zero dependencies.

</div>

```python
from fastapi import FastAPI, Depends
from tollbooth.integrations.fastapi import TollboothMiddleware

app = FastAPI()
app.add_middleware(TollboothMiddleware, secret="your-secret-key")
```

Bots get a browser challenge page. Humans solve it once, get a cookie, browse freely.

## Why tollbooth over [Anubis](https://github.com/TecharoHQ/anubis)?

|                   | tollbooth                                 | Anubis                                                                                                          |
| ----------------- | ----------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Language**      | Python (drop-in middleware)               | Go (standalone reverse proxy)                                                                                   |
| **Dependencies**  | 0                                         | [31 direct, ~160 transitive](https://github.com/TecharoHQ/anubis/blob/main/go.mod#L3-L203)                      |
| **Code size**     | ~800 lines                                | ~10,000 lines                                                                                                   |
| **Integration**   | `app.add_middleware(...)`                 | Separate process + reverse proxy                                                                                |
| **PoW algorithm** | Balloon hashing (memory-hard)             | [Plain SHA-256](https://github.com/TecharoHQ/anubis/blob/main/lib/challenge/proofofwork/proofofwork.go#L35-L85) |
| **Rules format**  | JSON                                      | [YAML + CEL expressions](https://github.com/TecharoHQ/anubis/blob/main/lib/config/config.go#L58-L73)            |
| **Frameworks**    | Flask, Django, FastAPI, Starlette, Falcon | None (reverse proxy only)                                                                                       |

### Security: memory-hard PoW

Anubis uses [plain SHA-256 hashing](https://github.com/TecharoHQ/anubis/blob/main/lib/challenge/proofofwork/proofofwork.go#L35-L85) — fast on GPUs and ASICs. An attacker with a GPU farm can solve challenges orders of magnitude faster than a browser.

Tollbooth uses **Balloon hashing** (Boneh, Corrigan-Gibbs, Schechter 2016) — a memory-hard function that requires `spaceCost * 32 bytes` per attempt. GPU parallelism is bottlenecked by memory bandwidth, not compute. This makes mass-solving economically impractical.

### Integration: middleware vs reverse proxy

Anubis runs as a [separate process with a reverse proxy](https://github.com/TecharoHQ/anubis/blob/main/cmd/anubis/main.go#L211-L265), adding network hops, deployment complexity, and a new failure domain.

Tollbooth is a middleware — it lives in your process, shares your config, and adds zero infrastructure:

```python
# WSGI (Flask, Django)
app = TollboothWSGI(app, secret="key")

# ASGI (FastAPI, Starlette)
app = TollboothASGI(app, secret="key")
```

### Rules: JSON vs YAML+CEL

Anubis requires [YAML policies with optional CEL expressions](https://github.com/TecharoHQ/anubis/blob/main/data/botPolicies.yaml) and [a complex config struct](https://github.com/TecharoHQ/anubis/blob/main/lib/config/config.go#L58-L73) with GeoIP, ASN, Thoth subscriptions, and 30+ CLI flags.

Tollbooth: one JSON file, four actions, regex matching.

### Performance: in-process vs network hop

Anubis [proxies every request through a separate Go process](https://github.com/TecharoHQ/anubis/blob/main/lib/anubis.go#L187-L296) — the full request pipeline includes reverse proxy setup, header rewriting, and upstream forwarding.

Tollbooth evaluates rules in-process with zero serialization. Allowed requests add microseconds of overhead. Challenged requests are handled before your app even sees them.

## Install

```bash
pip install tollbooth
```

With framework extras:

```bash
pip install tollbooth[flask]
pip install tollbooth[django]
pip install tollbooth[fastapi]
pip install tollbooth[starlette]
pip install tollbooth[falcon]
```

## How it works

```
Browser                             Server
  │                                   │
  │  GET /page                        │
  │──────────────────────────────────►│
  │                                   │  rules evaluate request
  │  429 + challenge page             │  → action: challenge
  │◄──────────────────────────────────│
  │                                   │
  │  Web Workers solve PoW            │
  │  Balloon(random_data + nonce)     │
  │  until ≥ difficulty leading       │
  │  zero bits in hash                │
  │                                   │
  │  POST /.tollbooth/verify          │
  │  { id, nonce, redirect }          │
  │──────────────────────────────────►│
  │                                   │  server verifies PoW
  │  302 + Set-Cookie (JWT)           │  → issues signed cookie
  │◄──────────────────────────────────│
  │                                   │
  │  GET /page (with cookie)          │
  │──────────────────────────────────►│
  │  200 OK                           │  cookie valid → pass through
  │◄──────────────────────────────────│
```

The challenge page uses `navigator.hardwareConcurrency` Web Workers to mine in parallel. The JWT cookie is HMAC-SHA256 signed, bound to the client's IP hash, and valid for 7 days.

## Usage

### Raw WSGI / ASGI

```python
from tollbooth import TollboothWSGI, TollboothASGI

# WSGI
app = TollboothWSGI(your_app, secret="your-secret-key")

# ASGI
app = TollboothASGI(your_app, secret="your-secret-key")
```

### Flask

```python
from flask import Flask
from tollbooth.integrations.flask import Tollbooth

app = Flask(__name__)
tb = Tollbooth(app, secret="your-secret-key")

@app.route("/")
def index():
    return "Hello!"

@tb.exempt
@app.route("/health")
def health():
    return "ok"
```

### Django

```python
# settings.py
TOLLBOOTH = {"secret": "your-secret-key"}
MIDDLEWARE = [
    "tollbooth.integrations.django.TollboothMiddleware",
    # ...
]
```

Per-view exemption:

```python
from tollbooth.integrations.django import tollbooth_exempt

@tollbooth_exempt
def health(request):
    return HttpResponse("ok")
```

### FastAPI

```python
from fastapi import FastAPI
from tollbooth.integrations.fastapi import TollboothMiddleware

app = FastAPI()
app.add_middleware(TollboothMiddleware, secret="your-secret-key")
```

Or as a dependency for specific routes:

```python
from tollbooth.integrations.fastapi import TollboothDep

protect = TollboothDep("your-secret-key")

@app.get("/protected", dependencies=[Depends(protect)])
def protected():
    return {"ok": True}
```

### Starlette

```python
from starlette.applications import Starlette
from tollbooth.integrations.starlette import TollboothMiddleware

app = Starlette()
app.add_middleware(TollboothMiddleware, secret="your-secret-key")
```

### Falcon

```python
import falcon
from tollbooth.integrations.falcon import TollboothMiddleware

app = falcon.App(middleware=[
    TollboothMiddleware(secret="your-secret-key"),
])
```

## Configuration

Pass options as keyword arguments to any integration:

```python
TollboothWSGI(
    app,
    secret="your-secret-key",
    default_difficulty=12,    # leading zero bits (default: 10)
    space_cost=2048,          # balloon memory blocks (default: 1024)
    time_cost=1,              # mixing rounds (default: 1)
    delta=3,                  # random lookups per step (default: 3)
    cookie_ttl=86400,         # cookie lifetime seconds (default: 604800)
    challenge_ttl=1800,       # challenge validity seconds (default: 1800)
    challenge_threshold=5,    # weight sum to trigger challenge (default: 5)
    branding=True,            # show "Protected by tollbooth" (default: True)
)
```

Each +1 difficulty doubles expected solve time. Higher `space_cost` increases memory per attempt (`space_cost * 32` bytes).

## Rules

Rules are evaluated top-to-bottom. First matching terminal action (`allow`, `deny`, `challenge`) wins. `weigh` rules accumulate weight — if the sum reaches `challenge_threshold`, a challenge is issued.

### Format

```json
[
    {
        "name": "rule-name",
        "action": "allow | deny | challenge | weigh",
        "user_agent": "regex",
        "path": "regex",
        "headers": { "Header-Name": "regex" },
        "remote_addresses": ["192.168.0.0/24"],
        "difficulty": 12,
        "weight": 3
    }
]
```

All match fields are optional. A rule with no match fields matches everything. All fields use regex except `remote_addresses` (CIDR notation).

### Actions

| Action      | Behavior                                   |
| ----------- | ------------------------------------------ |
| `allow`     | Pass through immediately                   |
| `deny`      | Return 403                                 |
| `challenge` | Serve PoW challenge page                   |
| `weigh`     | Add `weight` to score, continue evaluating |

### Default rules

Tollbooth ships with [rules.json](rules.json) covering:

**Deny** — Cloudflare Workers abuse, known bad bots, vulnerability scanners, WordPress probes, dotfile probes, shell probes, path traversal attempts

**Allow** — `.well-known/`, `favicon.ico`, `robots.txt`, health checks, search engines, feed readers, monitoring services, link previews, archive.org

**Challenge** — AI bots (difficulty 10), headless browsers (6), aggressive scrapers (8), empty user agents (6), generic browsers

**Weigh** — curl/wget (+3), missing Accept header (+3), missing Accept-Language (+2), `Connection: close` (+2)

### Custom rules

Override by passing a `rules_file` path or constructing a `Policy` directly:

```python
from tollbooth import Policy, Rule, TollboothWSGI

policy = Policy(rules=[
    Rule(name="internal", action="allow",
         remote_addresses=["10.0.0.0/8"]),
    Rule(name="api-bots", action="challenge",
         path="^/api/", difficulty=14),
    Rule(name="default", action="challenge"),
])

app = TollboothWSGI(your_app, secret="key", policy=policy)
```

### Rule templates

Block AI scrapers:

```json
{
    "name": "ai-bots",
    "action": "deny",
    "user_agent": "(?i:GPTBot|ChatGPT|Claude-Web|CCBot|Bytespider)"
}
```

Protect API endpoints:

```json
{ "name": "api-protect", "action": "challenge", "path": "^/api/", "difficulty": 14 }
```

Allowlist internal IPs:

```json
{ "name": "internal", "action": "allow", "remote_addresses": ["10.0.0.0/8", "172.16.0.0/12"] }
```

Weight scoring for suspicious signals:

```json
[
    { "name": "no-accept", "action": "weigh", "weight": 3, "headers": { "Accept": "^$" } },
    { "name": "no-lang", "action": "weigh", "weight": 2, "headers": { "Accept-Language": "^$" } },
    { "name": "curl", "action": "weigh", "weight": 3, "user_agent": "(?i:^curl/|^Wget/)" }
]
```

With `challenge_threshold=5`, curl (weight 3) + missing Accept-Language (weight 2) = 5, triggers a challenge.

## Integrations

All integrations share the same options via `TollboothBase`:

```python
from tollbooth.integrations.base import TollboothBase

tb = TollboothBase(
    secret="key",
    exclude=[r"^/static/", r"^/health$"],  # regex skip list
    json_mode=True,  # return JSON instead of HTML challenges
)
```

| Integration   | Middleware class      | Per-route            | Exempt decorator    |
| ------------- | --------------------- | -------------------- | ------------------- |
| **Flask**     | `Tollbooth(app)`      | `@tb.protect`        | `@tb.exempt`        |
| **Django**    | `TollboothMiddleware` | `@tollbooth_protect` | `@tollbooth_exempt` |
| **FastAPI**   | `TollboothMiddleware` | `TollboothDep`       | `exclude=[...]`     |
| **Starlette** | `TollboothMiddleware` | —                    | `exclude=[...]`     |
| **Falcon**    | `TollboothMiddleware` | `tollbooth_hook`     | `exclude=[...]`     |
| **WSGI**      | `TollboothWSGI`       | —                    | —                   |
| **ASGI**      | `TollboothASGI`       | —                    | —                   |

### JSON mode

For API/SPA backends, enable `json_mode=True`. Challenges return JSON instead of HTML:

```json
{
    "challenge": {
        "id": "abc123",
        "data": "random_hex",
        "difficulty": 10,
        "space_cost": 1024,
        "time_cost": 1,
        "delta": 3,
        "verify_path": "/.tollbooth/verify",
        "redirect": "/api/data"
    }
}
```

Solve with the [sha256-balloon](../sha256-balloon/) client library and POST the nonce to the verify endpoint.

## License

[MIT](../LICENSE)
