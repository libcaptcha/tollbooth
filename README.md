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

|                   | tollbooth                      | Anubis                                                                                                          |
| ----------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| **Language**      | Python (drop-in middleware)    | Go (standalone reverse proxy)                                                                                   |
| **Dependencies**  | 0                              | [31 direct, ~160 transitive](https://github.com/TecharoHQ/anubis/blob/main/go.mod#L3-L203)                      |
| **Code size**     | ~800 lines                     | ~10,000 lines                                                                                                   |
| **Integration**   | `app.add_middleware(...)`      | Separate process + reverse proxy                                                                                |
| **PoW algorithm** | Balloon hashing (memory-hard)  | [Plain SHA-256](https://github.com/TecharoHQ/anubis/blob/main/lib/challenge/proofofwork/proofofwork.go#L35-L85) |
| **Rules format**  | JSON                           | [YAML + CEL expressions](https://github.com/TecharoHQ/anubis/blob/main/lib/config/config.go#L58-L73)            |
| **Frameworks**    | Flask, Django, FastAPI, Falcon | None (reverse proxy only)                                                                                       |

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

## Starlette

```python
from starlette.applications import Starlette
from tollbooth import TollboothASGI

app = Starlette()
app = TollboothASGI(app, secret="your-secret-key")
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
        "weight": 3,
        "blocklist": false
    }
]
```

All match fields are optional. A rule with no match fields matches everything. All fields use regex except `remote_addresses` (CIDR notation) and `blocklist` (boolean).

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

**Challenge** — IP blocklist, AI bots (difficulty 14), headless browsers (12), aggressive scrapers (12), empty user agents, generic browsers

**Weigh** — curl/wget (+3), missing Accept header (+3), missing Accept-Language (+2), `Connection: close` (+2)

### Custom rules

Override by passing a `rules_file` into `TollboothWSGI` or constructing a `Policy` directly:

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

## IP Blocklist

Challenge known malicious IPs using [tn3w/IPBlocklist](https://github.com/tn3w/IPBlocklist). The blocklist supports single IPs, CIDR blocks, and IP ranges for both IPv4 and IPv6.

Rules with `"blocklist": true` only match if the client IP is in the loaded blocklist. The default [rules.json](tollbooth/rules.json) includes an `ip-blocklist` rule (challenge, difficulty 8).

### In-memory

```python
from tollbooth import Engine, IPBlocklist

blocklist = IPBlocklist()
blocklist.load()  # downloads from GitHub
# or: blocklist.load("/path/to/blocklist.txt")

engine = Engine("your-secret-key", blocklist=blocklist)
```

Uses sorted arrays with O(log n) binary search. The 23MB text file is parsed into compact integer ranges — fast lookups, no dependencies.

```python
blocklist.start_updates(interval=86400)  # daily refresh
```

### Redis-backed

For multi-process deployments, store the blocklist in Redis so each instance doesn't hold it in memory:

```python
import redis
from tollbooth.redis import RedisEngine, RedisIPBlocklist

client = redis.Redis()

blocklist = RedisIPBlocklist(client)
blocklist.load()  # parses + stores in Redis sorted sets

engine = RedisEngine(client, secret="key", blocklist=blocklist)
```

Lookups execute a server-side Lua script — one network roundtrip, O(log n) via `ZREVRANGEBYLEX`. IPv4 and IPv6 are stored in separate sorted sets with hex-encoded keys for correct lexicographic ordering.

`start_updates` uses a Redis `SET NX EX` lock so only one instance across all processes performs the download — others skip until the lock expires:

```python
blocklist.start_updates(interval=86400)  # safe to call on every instance
```

### Custom blocklist rule

```json
{ "name": "block-bad-ips", "action": "deny", "blocklist": true }
```

Without a loaded blocklist, `blocklist` rules are silently skipped.

## Redis

Share challenges, secret, config, and rules across instances via Redis (or any compatible server like Dragonfly, KeyDB, Valkey).

```bash
pip install tollbooth[redis]
```

```python
import redis
from tollbooth.redis import RedisEngine

client = redis.Redis(host="127.0.0.1", port=6379)

# First instance — sets secret + config in Redis
engine = RedisEngine(client, secret="your-secret-key")

# Other instances — load secret + config from Redis
engine2 = RedisEngine(client)
```

Use with any integration via `TollboothBase`:

```python
from tollbooth.integrations.flask import Tollbooth
from tollbooth.redis import RedisEngine

engine = RedisEngine(client, secret="your-secret-key")
tb = Tollbooth(app, engine=engine)
```

Changes propagate automatically via pub/sub (`auto_sync=True` by default):

```python
engine.update_secret("new-secret")
engine.update_policy(default_difficulty=14, space_cost=2048)
engine.update_rules([Rule(name="block", action="deny", path="/admin")])

# Manual sync (if auto_sync=False)
engine2.sync()
```

All challenges are stored in Redis with TTL — no in-memory state, no cleanup needed. Use `prefix` to namespace multiple tollbooth deployments on the same Redis instance:

```python
RedisEngine(client, secret="key", prefix="myapp:tollbooth")
```

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

| Integration | Middleware class      | Per-route            | Exempt decorator    |
| ----------- | --------------------- | -------------------- | ------------------- |
| **Flask**   | `Tollbooth(app)`      | `@tb.protect`        | `@tb.exempt`        |
| **Django**  | `TollboothMiddleware` | `@tollbooth_protect` | `@tollbooth_exempt` |
| **FastAPI** | `TollboothMiddleware` | `TollboothDep`       | `exclude=[...]`     |
| **Falcon**  | `TollboothMiddleware` | `tollbooth_hook`     | `exclude=[...]`     |
| **WSGI**    | `TollboothWSGI`       | —                    | —                   |
| **ASGI**    | `TollboothASGI`       | —                    | —                   |

### JSON mode

For API/SPA backends, `json_mode` controls whether challenges return JSON instead of HTML. It accepts a `bool` or a callable `(request) -> bool` for per-request control:

```python
# all routes return JSON
TollboothBase(secret="key", json_mode=True)

# only /api/* routes return JSON
TollboothBase(
    secret="key",
    json_mode=lambda req: req["path"].startswith("/api/"),
)
```

JSON challenge response:

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

## Tests

```bash
pip install tollbooth[test]
pytest tests/
```

Framework integration tests and Redis tests are skipped automatically if the required packages or services are not available.

To run all tests:

```bash
pip install tollbooth[test,flask,django,fastapi,falcon,redis]
pytest tests/ -v
```

Redis tests (`tests/test_redis.py`) require a running Redis-compatible server at `127.0.0.1:6379`. If unavailable, they are skipped with a clear message.

## Formatting

```bash
pip install black isort
isort .
black .
npx prtfm
```

## License

[MIT](LICENSE)
