<div align="center">

# tollbooth

A bot-challenge Python middleware issuing brief challenges, granting solvers signed access cookies.

</div>

```python
from fastapi import FastAPI
from tollbooth.integrations.fastapi import TollboothMiddleware

app = FastAPI()
app.add_middleware(TollboothMiddleware, secret="your-secret-key")
```

Bots get a browser challenge page. Humans solve it once, get a cookie, browse freely.

## Screenshots

**ImageCaptcha() Solution: `NWGT5V`**

<img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/image-captcha.webp" alt="Image CAPTCHA challenge page" width="400">

**SHA256Balloon() `Default`**

<img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/sha256.webp" alt="SHA256 challenge page" width="400">

## Contents

- [Screenshots](#screenshots)
- [Install](#install)
- [How it works](#how-it-works)
- [Usage](#usage)
    - [Flask](#flask)
    - [Django](#django)
    - [FastAPI](#fastapi)
    - [Starlette](#starlette)
    - [Falcon](#falcon)
    - [Raw WSGI / ASGI](#raw-wsgi--asgi)
- [Challenge types](#challenge-types)
    - [SHA256Balloon & SHA256](#sha256balloon--sha256)
        - [Tuning](#tuning)
    - [Image CAPTCHA](#image-captcha)
        - [Setup](#setup)
    - [Difficulty reference](#difficulty-reference)
- [Configuration](#configuration)
- [Rules](#rules)
    - [Rule fields](#rule-fields)
    - [Actions](#actions)
    - [Default rules](#default-rules)
    - [Custom policy examples](#custom-policy-examples)
- [Integrations](#integrations)
    - [Reusing an engine across integrations](#reusing-an-engine-across-integrations)
    - [JSON mode](#json-mode)
- [IP Blocklist](#ip-blocklist)
    - [In-memory](#in-memory)
    - [Redis-backed](#redis-backed)
    - [Blocklist rules](#blocklist-rules)
- [Redis](#redis)
- [Tests](#tests)
- [Managing screenshots](#managing-screenshots)
- [License](#license)

## Install

```bash
pip install tollbooth
pip install tollbooth[flask]     # Flask
pip install tollbooth[django]    # Django
pip install tollbooth[fastapi]   # FastAPI
pip install tollbooth[falcon]    # Falcon
pip install tollbooth[starlette] # Starlette
pip install tollbooth[redis]     # Redis backend
pip install tollbooth[image]     # Image CAPTCHA (Pillow)
```

## How it works

```
  Browser                            Server
     │                                  │
     │  GET /protected                  │
     │─────────────────────────────────►│ ◄── rule engine evaluates
     │                                  │     User-Agent, path, IP…
     │◄─────────────────────────────────│
     │  429  ┌──────────────────────┐   │
     │       │  Checking your       │   │
     │       │  browser… 72 H/s     │   │
     │       └──────────────────────┘   │
     │                                  │
     │  Web Workers compute             │
     │  Balloon(random_data+nonce)      │
     │  until hash has ≥N leading       │
     │  zero bits                       │
     │                                  │
     │  POST /.tollbooth/verify         │
     │  { id, nonce, redirect }         │
     │─────────────────────────────────►│ ◄── server re-runs hash,
     │                                  │     checks leading zeros
     │◄─────────────────────────────────│
     │  302  Set-Cookie: _tollbooth=JWT │
     │                                  │
     │  GET /protected  Cookie: …JWT    │
     │─────────────────────────────────►│ ◄── JWT valid + IP matches
     │  200 OK                          │     → pass through
     │◄─────────────────────────────────│
```

The cookie is HMAC-SHA256 signed, bound to the client IP hash, and valid for 7 days by default. Solved challenges are marked spent — nonces cannot be reused.

### Rule evaluation

```
incoming request
      │
      ▼
 ┌─────────────────────────────────────┐
 │  rule 1: action=allow  path=/health │──── matches? ──► ALLOW (pass through)
 ├─────────────────────────────────────┤
 │  rule 2: action=deny   ua=sqlmap    │──── matches? ──► DENY  (403)
 ├─────────────────────────────────────┤
 │  rule 3: action=challenge ua=GPTBot │──── matches? ──► CHALLENGE
 ├─────────────────────────────────────┤
 │  rule 4: action=weigh  +3  no UA    │──── matches? ──► weight += 3
 ├─────────────────────────────────────┤
 │  rule 5: action=weigh  +2  no lang  │──── matches? ──► weight += 2
 └─────────────────────────────────────┘
      │
      ▼
 weight ≥ threshold? ──► CHALLENGE
      │
      ▼
     ALLOW
```

## Usage

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

@tb.protect(difficulty=14)
@app.route("/api/data")
def data():
    return {"rows": [...]}
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

```python
# views.py
from tollbooth.integrations.django import tollbooth_exempt, tollbooth_protect

@tollbooth_exempt
def health(request):
    return HttpResponse("ok")

@tollbooth_protect(difficulty=14)
def api_data(request):
    return JsonResponse({"rows": [...]})
```

### FastAPI

```python
from fastapi import FastAPI, Depends
from tollbooth.integrations.fastapi import TollboothMiddleware, TollboothDep

# Protect all routes (JSON mode on by default)
app = FastAPI()
app.add_middleware(TollboothMiddleware, secret="your-secret-key")
```

Route-level protection — only challenged routes pay the PoW cost:

```python
protect = TollboothDep("your-secret-key")

@app.get("/public")
def public():
    return {"open": True}

@app.get("/protected", dependencies=[Depends(protect)])
def protected():
    return {"secret": True}
```

### Starlette

```python
from starlette.applications import Starlette
from tollbooth.integrations.starlette import TollboothMiddleware

app = Starlette(routes=[...])
app = TollboothMiddleware(app, secret="your-secret-key")
```

### Falcon

```python
import falcon
from tollbooth.integrations.falcon import TollboothMiddleware, tollbooth_hook

app = falcon.App(middleware=[TollboothMiddleware(secret="your-secret-key")])
```

Per-resource with a hook:

```python
from tollbooth.integrations.falcon import tollbooth_hook

hook = tollbooth_hook("your-secret-key", difficulty=14)

class SensitiveResource:
    @falcon.before(hook)
    def on_get(self, req, resp):
        resp.media = {"rows": [...]}
```

### Raw WSGI / ASGI

```python
from tollbooth import TollboothWSGI, TollboothASGI

app = TollboothWSGI(wsgi_app, secret="your-secret-key")  # Flask, Django, …
app = TollboothASGI(asgi_app, secret="your-secret-key")  # FastAPI, Starlette, …
```

## Challenge types

Difficulty is expressed in **SHA256-Balloon units** — each type applies its own offset so equal numbers mean equal expected work.

```
difficulty=10 (policy setting)
      │
      ├── SHA256Balloon  offset  +0  →  effective 10   ~1 024 hashes × 32 KB/hash
      ├── SHA256         offset  +6  →  effective 16   ~65 536 hashes  (no memory cost)
      └── ImageCaptcha   offset  -4  →  effective  6   6-character solution
```

| Type             | Class           | Offset | Solved by  | GPU-resistant |
| ---------------- | --------------- | ------ | ---------- | ------------- |
| `sha256-balloon` | `SHA256Balloon` | +0     | browser JS | ✓             |
| `sha256`         | `SHA256`        | +6     | browser JS | ✗             |
| `image-captcha`  | `ImageCaptcha`  | -4     | human      | ✓             |

### SHA256Balloon & SHA256

Both are browser proof-of-work challenges solved automatically by JavaScript. `SHA256Balloon` is memory-hard (GPU-resistant); `SHA256` has no memory requirement but applies offset +6 to compensate. Use `SHA256Balloon` by default; use `SHA256` when client environment is constrained or solve speed matters more than GPU resistance.

#### Tuning

```python
from tollbooth import SHA256Balloon, SHA256, TollboothWSGI

# Default — memory-hard, GPU-resistant (32 KB per attempt)
app = TollboothWSGI(app, secret="key")

# Heavier — 64 KB, harder to parallelize
app = TollboothWSGI(app, secret="key",
    challenge_handler=SHA256Balloon(space_cost=2048))

# Plain SHA256 — faster, no memory cost, higher difficulty to compensate
app = TollboothWSGI(app, secret="key",
    challenge_handler=SHA256(), default_difficulty=14)
```

### Image CAPTCHA

Human-solved visual challenge. Renders distorted alphanumeric characters over a background using system fonts, with random per-character rotation, color, and position, plus line and noise overlays. Solution length scales with difficulty (offset -4): difficulty 10 → 6 characters. Solution is HMAC-encrypted in the challenge store — never stored in plaintext. Requires `Pillow`:

```bash
pip install tollbooth[image]
```

#### Setup

```python
from tollbooth import ImageCaptcha, TollboothWSGI

app = TollboothWSGI(
    app,
    secret="your-secret-key",          # also used to sign CAPTCHA solution tokens
    challenge_handler=ImageCaptcha(
        backgrounds_path="/path/to/backgrounds", # optional directory of .jpg files
        token_ttl=1800,                          # solution token lifetime in seconds
    ),
)
```

System fonts are detected automatically from common OS directories. Only fonts from known Latin families (DejaVu, Fira, Liberation, Ubuntu, etc.) are used. Background images are optional — falls back to a solid fill.

### Difficulty reference

Expected hashes to solve (2^difficulty). Each +1 doubles solve time.

```
 difficulty │  SHA256-Balloon  │     SHA256
────────────┼──────────────────┼────────────────
     8      │       256        │      16 384  (+6)
    10      │      1 024       │      65 536
    12      │      4 096       │     262 144
    14      │     16 384       │   1 048 576
    16      │     65 536       │   4 194 304
    20      │  1 048 576       │  67 108 864
```

Typical browser solve time at difficulty 10 (SHA256-Balloon, 4 cores): **~0.5 s**

## Configuration

```python
from tollbooth import SHA256Balloon, TollboothWSGI

TollboothWSGI(
    app,
    secret="your-secret-key",         # required — signs cookies + HMAC
    default_difficulty=10,             # baseline PoW difficulty (default: 10)
    challenge_handler=SHA256Balloon(   # algorithm + its parameters
        space_cost=1024,               #   memory blocks per attempt (default: 1024)
        time_cost=1,                   #   mixing rounds (default: 1)
        delta=3,                       #   random lookups per step (default: 3)
    ),
    challenge_threshold=5,             # weight sum to trigger challenge (default: 5)
    cookie_ttl=604800,                 # cookie lifetime in seconds (default: 7 days)
    challenge_ttl=1800,                # challenge expiry in seconds (default: 30 min)
    branding=True,                     # "Protected by tollbooth" footer (default: True)
    exclude=[r"^/static/", r"^/_/"],   # paths that bypass all checks
)
```

## Rules

Rules are evaluated top-to-bottom. The first matching terminal action (`allow`, `deny`, `challenge`) wins. `weigh` rules accumulate a score — when it reaches `challenge_threshold`, a challenge is issued.

### Rule fields

```json
{
    "name": "rule-name",
    "action": "allow | deny | challenge | weigh",
    "user_agent": "regex",
    "path": "regex",
    "headers": { "Header-Name": "value-regex" },
    "remote_addresses": ["10.0.0.0/8", "2001:db8::/32"],
    "difficulty": 14,
    "weight": 3,
    "blocklist": false
}
```

All match fields are optional and ANDed together. A rule with no match fields matches everything. `remote_addresses` uses CIDR notation; all other string fields use regex.

### Actions

| Action      | Effect                                         |
| ----------- | ---------------------------------------------- |
| `allow`     | Pass through immediately, skip remaining rules |
| `deny`      | Return 403 Forbidden                           |
| `challenge` | Issue PoW challenge at given `difficulty`      |
| `weigh`     | Add `weight` to running score, keep going      |

### Default rules

Tollbooth ships with [rules.json](tollbooth/rules.json) covering common traffic patterns out of the box:

| Category      | Examples                                                                                 |
| ------------- | ---------------------------------------------------------------------------------------- |
| **Deny**      | sqlmap, Acunetix, Nmap, `.env`/`.git` probes, shell probes, path traversal               |
| **Allow**     | Googlebot, Bingbot, UptimeRobot, Pingdom, Slack/Discord previews, archive.org            |
| **Challenge** | AI crawlers (GPT/Claude/CCBot, diff=14), headless browsers (diff=12), Scrapy (diff=12)   |
| **Weigh**     | curl/wget (+3), missing Accept (+3), missing Accept-Language (+2), Connection:close (+2) |

### Custom policy examples

Allow internal network, challenge everything else:

```python
from tollbooth import Policy, Rule, TollboothWSGI

policy = Policy(rules=[
    Rule(name="internal", action="allow", remote_addresses=["10.0.0.0/8"]),
    Rule(name="health",   action="allow", path=r"^/health$"),
    Rule(name="default",  action="challenge"),
])
app = TollboothWSGI(your_app, secret="key", policy=policy)
```

Tiered difficulty — harder challenge for scrapers, lighter for everyone else:

```python
policy = Policy(
    default_difficulty=8,
    rules=[
        Rule(name="scrapers", action="challenge", difficulty=16,
             user_agent=r"(?i:python-requests|scrapy|curl)"),
        Rule(name="default",  action="challenge"),
    ],
)
```

Block AI bots entirely, challenge everything else:

```json
[
    {
        "name": "ai-deny",
        "action": "deny",
        "user_agent": "(?i:GPTBot|ChatGPT|Claude-Web|CCBot|Bytespider|Diffbot)"
    },
    { "name": "default", "action": "challenge" }
]
```

Weight-based scoring — no single rule triggers a challenge, but combinations do:

```json
[
    { "name": "curl", "action": "weigh", "weight": 3, "user_agent": "(?i:^curl/|^Wget/)" },
    { "name": "no-ua", "action": "weigh", "weight": 3, "user_agent": "^$" },
    { "name": "no-lang", "action": "weigh", "weight": 2, "headers": { "Accept-Language": "^$" } },
    { "name": "no-accept", "action": "weigh", "weight": 2, "headers": { "Accept": "^$" } }
]
```

With `challenge_threshold=5`: curl alone (3) passes, no-UA (3) passes, but curl + no-lang (5) triggers a challenge.

Path-specific rules — protect `/admin` hard, leave everything else on defaults:

```json
[
    {
        "name": "admin-block",
        "action": "deny",
        "path": "^/admin",
        "user_agent": "(?i:bot|spider|scraper)"
    },
    { "name": "admin-challenge", "action": "challenge", "path": "^/admin", "difficulty": 16 }
]
```

## Integrations

All framework integrations accept the same keyword arguments as `TollboothWSGI`/`TollboothASGI`.

| Integration   | Import                             | Middleware class      | Per-route            | Exempt              |
| ------------- | ---------------------------------- | --------------------- | -------------------- | ------------------- |
| **Flask**     | `tollbooth.integrations.flask`     | `Tollbooth(app)`      | `@tb.protect`        | `@tb.exempt`        |
| **Django**    | `tollbooth.integrations.django`    | `TollboothMiddleware` | `@tollbooth_protect` | `@tollbooth_exempt` |
| **FastAPI**   | `tollbooth.integrations.fastapi`   | `TollboothMiddleware` | `TollboothDep`       | `exclude=[...]`     |
| **Falcon**    | `tollbooth.integrations.falcon`    | `TollboothMiddleware` | `tollbooth_hook`     | `exclude=[...]`     |
| **Starlette** | `tollbooth.integrations.starlette` | `TollboothMiddleware` | —                    | `exclude=[...]`     |
| **WSGI**      | `tollbooth`                        | `TollboothWSGI`       | —                    | —                   |
| **ASGI**      | `tollbooth`                        | `TollboothASGI`       | —                    | —                   |

### Reusing an engine across integrations

```python
from tollbooth import Engine, Policy, Rule
from tollbooth.integrations.flask import Tollbooth

engine = Engine(
    secret="your-secret-key",
    policy=Policy(rules=[Rule(name="all", action="challenge")]),
)

# Pass the same engine to multiple integrations
tb_flask = Tollbooth(flask_app, engine=engine)
tb_asgi  = TollboothASGI(asgi_app, engine=engine)
```

### JSON mode

For API/SPA backends where browsers aren't involved, `json_mode=True` returns structured JSON instead of an HTML challenge page:

```python
# FastAPI uses json_mode=True by default
app.add_middleware(TollboothMiddleware, secret="key")

# Enable for all routes on any integration
TollboothBase(secret="key", json_mode=True)

# Enable only for /api/* routes
TollboothBase(secret="key", json_mode=lambda req: req["path"].startswith("/api/"))
```

SHA256-Balloon challenge response:

```json
{
    "challenge": {
        "id": "Xk9mP2...",
        "data": "a3f1...",
        "difficulty": 10,
        "spaceCost": 1024,
        "timeCost": 1,
        "delta": 3,
        "verifyPath": "/.tollbooth/verify",
        "redirect": "/api/data"
    }
}
```

SHA256 challenge response (no memory parameters):

```json
{
    "challenge": {
        "id": "Xk9mP2...",
        "data": "a3f1...",
        "difficulty": 16,
        "verifyPath": "/.tollbooth/verify",
        "redirect": "/api/data"
    }
}
```

Verify by POSTing the solved nonce:

```
POST /.tollbooth/verify
Content-Type: application/x-www-form-urlencoded

id=Xk9mP2...&nonce=38471&redirect=/api/data
```

Response on success: `302 Location: /api/data  Set-Cookie: _tollbooth=<JWT>`

## IP Blocklist

Challenge or block known malicious IPs using [tn3w/IPBlocklist](https://github.com/tn3w/IPBlocklist). Supports single IPs, CIDR ranges, and IP ranges for IPv4 and IPv6.

### In-memory

```python
from tollbooth import Engine, IPBlocklist

blocklist = IPBlocklist()
blocklist.load()                        # downloads ~23 MB from GitHub
blocklist.load("/path/to/list.txt")    # or load from file

engine = Engine("your-secret-key", blocklist=blocklist)
blocklist.start_updates(interval=86400) # optional daily refresh
```

Parsed into compact integer ranges with O(log n) binary search. No dependencies.

### Redis-backed

For multi-process deployments — one download, shared across all workers:

```python
import redis
from tollbooth.redis import RedisEngine, RedisIPBlocklist

client = redis.Redis()
blocklist = RedisIPBlocklist(client)
blocklist.load()  # download once, store in Redis sorted sets

engine = RedisEngine(client, secret="key", blocklist=blocklist)
blocklist.start_updates(interval=86400)  # distributed lock — only one process downloads
```

Lookups use a server-side Lua script: one roundtrip, O(log n) via `ZREVRANGEBYLEX`.

### Blocklist rules

```json
{ "name": "known-bad", "action": "challenge", "blocklist": true }
{ "name": "known-bad", "action": "deny",      "blocklist": true }
```

Rules with `"blocklist": true` are silently skipped when no blocklist is loaded.

## Redis

Share challenges, secret, config, and rules across workers via Redis (or Dragonfly, KeyDB, Valkey).

```
 worker 1        worker 2        worker 3
    │               │               │
    └───────────────┴───────────────┘
                    │
              ┌─────▼──────┐
              │   Redis    │
              │ challenges │
              │   secret   │
              │   config   │
              └────────────┘
```

```bash
pip install tollbooth[redis]
```

```python
import redis
from tollbooth.redis import RedisEngine

client = redis.Redis(host="127.0.0.1", port=6379)

# First instance writes secret + config
engine = RedisEngine(client, secret="your-secret-key")

# Additional instances read from Redis — no secret needed
engine = RedisEngine(client)
```

Use with any integration:

```python
from tollbooth.integrations.fastapi import TollboothMiddleware
from tollbooth.redis import RedisEngine

engine = RedisEngine(client, secret="your-secret-key")
app.add_middleware(TollboothMiddleware, engine=engine)
```

Live config updates propagate to all workers via pub/sub:

```python
engine.update_secret("new-secret")
engine.update_policy(default_difficulty=14)
engine.update_rules([Rule(name="block", action="deny", path="^/admin")])

# Manual sync if auto_sync=False
engine.sync()
```

Namespace multiple deployments on one Redis instance:

```python
RedisEngine(client, secret="key", prefix="myapp")
RedisEngine(client, secret="key", prefix="staging")
```

## Tests

```bash
pip install tollbooth[test]
pytest tests/
```

Framework and Redis tests skip automatically if packages/services are unavailable.

```bash
pip install tollbooth[test,flask,django,fastapi,falcon,starlette,redis]
pytest tests/ -v
```

Redis tests require a server at `127.0.0.1:6379`.

## Formatting

```bash
pip install black isort
isort . && black .
npx prtfm
```

## Managing screenshots

Screenshots live on the orphan `screenshots` branch to keep binary assets out of the main history.

**Add or update a screenshot:**

```bash
git checkout screenshots
# add/replace image files
cp ~/new-screenshot.webp .
git add new-screenshot.webp
git commit -m "add new-screenshot.webp"
git push origin screenshots
git checkout main
```

**Reference in README:**

```markdown
<img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/filename.webp" alt="description" width="400">
```

## License

[MIT](LICENSE)
