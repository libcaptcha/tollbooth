<div align="center">

# tollbooth

A bot-challenge Python middleware issuing brief challenges, granting solvers signed access cookies.

[![PyPI](https://img.shields.io/pypi/v/tollbooth?style=flat-square)](https://pypi.org/project/tollbooth/)
[![Python](https://img.shields.io/pypi/pyversions/tollbooth?style=flat-square)](https://pypi.org/project/tollbooth/)
[![License](https://img.shields.io/github/license/libcaptcha/tollbooth?style=flat-square)](https://github.com/libcaptcha/tollbooth/blob/main/LICENSE)
[![Issues](https://img.shields.io/github/issues/libcaptcha/tollbooth?style=flat-square)](https://github.com/libcaptcha/tollbooth/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/libcaptcha/tollbooth/blob/main/CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/libcaptcha/tollbooth?style=flat-square)](https://github.com/libcaptcha/tollbooth/stargazers)
[![Downloads](https://img.shields.io/pypi/dm/tollbooth?style=flat-square)](https://pypi.org/project/tollbooth/)

</div>

```python
from flask import Flask
from tollbooth.integrations.flask import Tollbooth

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key"
tb = Tollbooth(app)  # uses SECRET_KEY automatically
```

Bots get a browser challenge page. Humans solve it once, get a cookie, browse freely.

## Screenshots

```python
from tollbooth import CharacterCaptcha, TollboothWSGI
app = TollboothWSGI(app, secret="key", challenge_handler=CharacterCaptcha())
```

**CharacterCaptcha() Solution: `U5R6H3`**

<div style="display: flex; gap: 10px;">
  <img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/character-captcha-light.webp" alt="Light" width="49%">
  <img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/character-captcha-dark.webp" alt="Dark" width="49%">
</div>

<br>

**SHA256 / SHA256Balloon() `Default`**

<div style="display: flex; gap: 10px;">
  <img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/sha256-balloon-light.webp" alt="Light" width="49%">
  <img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/sha256-balloon-dark.webp" alt="Dark" width="49%">
</div>

<br>

**SlidingCaptcha()**

<div style="display: flex; gap: 10px;">
  <img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/sliding-captcha-light.webp" alt="Light" width="49%">
  <img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/sliding-captcha-dark.webp" alt="Dark" width="49%">
</div>

<br>

**CircleCaptcha()**

<div style="display: flex; gap: 10px;">
  <img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/circle-captcha-light.webp" alt="Light" width="49%">
  <img src="https://raw.githubusercontent.com/libcaptcha/tollbooth/screenshots/circle-captcha-dark.webp" alt="Dark" width="49%">
</div>

## Contents

- [Screenshots](#screenshots)
- [Examples](#examples)
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
    - [Navigator Attestation](#navigator-attestation)
        - [Reading the score](#reading-the-score)
    - [Character CAPTCHA](#character-captcha)
        - [Setup](#setup)
    - [Sliding CAPTCHA](#sliding-captcha)
        - [Setup](#setup-1)
    - [Circle CAPTCHA](#circle-captcha)
        - [Setup](#setup-2)
    - [Third-party CAPTCHA challenge](#third-party-captcha-challenge)
        - [Setup](#setup-3)
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
- [Reading claims](#reading-claims)
- [IP Blocklist](#ip-blocklist)
    - [In-memory](#in-memory)
    - [Redis-backed](#redis-backed)
    - [Blocklist rules](#blocklist-rules)
- [Redis](#redis)
- [Third-party CAPTCHAs](#third-party-captchas)
- [Tests](#tests)
- [Contributing](#contributing)
- [Security](#security)
- [Managing screenshots](#managing-screenshots)
- [License](#license)

## Examples

Runnable examples for every integration and challenge type:

```
examples/
  general.py                  # WSGI + ASGI quickstart  (python examples/general.py [wsgi|asgi])
  integrations/
    wsgi.py                   # bare WSGI
    asgi.py                   # bare ASGI  (requires uvicorn)
    flask_app.py              # Flask middleware + per-route + exempt
    fastapi_app.py            # FastAPI middleware + dependency + verify
    starlette_app.py          # Starlette middleware
    django_app.py             # Django — self-contained, runs with runserver
    falcon_app.py             # Falcon middleware + per-resource hook
  challenges/
    sha256_balloon.py         # SHA256Balloon (default, memory-hard)
    sha256.py                 # SHA256 (faster, no memory cost)
    character_captcha.py      # Character CAPTCHA  (requires Pillow)
    sliding_captcha.py        # Sliding puzzle CAPTCHA  (requires Pillow)
    circle_captcha.py         # Click-the-incomplete-circle CAPTCHA  (requires Pillow)
    navigator_attestation.py  # Browser fingerprinting
    third_party_captcha.py    # Third-party CAPTCHA (pass provider as first arg)
```

## Install

```bash
pip install tollbooth
pip install tollbooth[flask]     # Flask
pip install tollbooth[django]    # Django
pip install tollbooth[fastapi]   # FastAPI
pip install tollbooth[falcon]    # Falcon
pip install tollbooth[starlette] # Starlette
pip install tollbooth[redis]     # Redis backend
pip install tollbooth[image]     # Character / Sliding CAPTCHA (Pillow)
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

Uses Flask's `SECRET_KEY` by default — no separate secret needed. All engine/policy values can be set via `app.config` with the `TOLLBOOTH_` prefix (`TOLLBOOTH_DEFAULT_DIFFICULTY`, `TOLLBOOTH_COOKIE_TTL`, etc.). Constructor kwargs override config values.

```python
from flask import Flask
from tollbooth.integrations.flask import Tollbooth

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key"
tb = Tollbooth(app)

@app.route("/")
def index():
    return "Hello!"

@tb.exempt
@app.route("/health")
def health():
    return "ok"
```

Config-driven setup (factory pattern):

```python
app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key"
app.config["TOLLBOOTH_DEFAULT_DIFFICULTY"] = 14
app.config["TOLLBOOTH_BRANDING"] = False
app.config["TOLLBOOTH_ACCENT_COLOR"] = "#ff4488"

tb = Tollbooth()
tb.init_app(app)
```

Explicit secret still works and takes priority:

```python
tb = Tollbooth(app, secret="override-secret", default_difficulty=12)
```

### Django

Uses Django's `SECRET_KEY` by default — no separate secret needed. Override with `TOLLBOOTH = {"secret": "..."}` if desired.

```python
# settings.py
SECRET_KEY = "your-secret-key"
TOLLBOOTH = {"default_difficulty": 14}  # secret falls back to SECRET_KEY
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
      ├── SHA256Balloon    offset  +0  →  effective 10   ~1 024 hashes × 32 KB/hash
      ├── SHA256           offset  +6  →  effective 16   ~65 536 hashes  (no memory cost)
      ├── CharacterCaptcha offset  -4  →  effective  6   6-character solution
      ├── SlidingCaptcha   offset  -4  →  effective  6   sliding puzzle
      └── CircleCaptcha    offset  -4  →  effective  6   click the incomplete circle
```

| Type                    | Class                  | Offset | Solved by    | GPU-resistant |
| ----------------------- | ---------------------- | ------ | ------------ | ------------- |
| `sha256-balloon`        | `SHA256Balloon`        | +0     | browser JS   | ✓             |
| `sha256`                | `SHA256`               | +6     | browser JS   | ✗             |
| `character-captcha`     | `CharacterCaptcha`     | -4     | human        | ✓             |
| `sliding-captcha`       | `SlidingCaptcha`       | -4     | human        | ✓             |
| `circle-captcha`        | `CircleCaptcha`        | -4     | human        | ✓             |
| `navigator-attestation` | `NavigatorAttestation` | +0     | browser (WS) | ✓             |

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

### Navigator Attestation

Passive browser fingerprinting challenge — no user interaction required. The challenge page opens a WebSocket to `/.tollbooth/attest`, runs 3 rounds of signal collection (browser APIs, automation markers, hardware consistency, rendering fingerprints, and 20+ other categories), then scores the result server-side.

```python
from tollbooth import NavigatorAttestation, TollboothASGI

app = TollboothASGI(
    asgi_app,
    secret="your-secret-key",
    challenge_handler=NavigatorAttestation(),
)
```

Difficulty controls the minimum score threshold required to pass (higher = stricter):

```
difficulty=5  → threshold 0.50  (suspicious browsers pass)
difficulty=10 → threshold 0.60  (default)
difficulty=15 → threshold 0.70
difficulty=20 → threshold 0.80
```

The signal validator is a full Python port of the `navigator-attestation` JS library. Scoring covers automation globals, Selenium/CDP artifacts, stealth plugin markers, headless heuristics, VM detection, canvas/WebGL fingerprints, and cross-signal consistency checks. The attestation token is HMAC-signed with a per-challenge secret and expires after 5 minutes.

#### Reading the score

`score` (0.0–1.0) is available on the [claims object](#reading-claims) after a visitor passes. It is `None` for PoW challenges (SHA256Balloon / SHA256 / CharacterCaptcha / SlidingCaptcha) — only `NavigatorAttestation` embeds it.

```python
# Flask
score = g.tollbooth.score

# Django / FastAPI / Starlette / Falcon — see Reading claims
score = request.state.tollbooth.score
```

### Character CAPTCHA

Human-solved visual challenge. Renders distorted alphanumeric characters over a background using system fonts, with random per-character rotation, color, and position, plus line and noise overlays. Solution length scales with difficulty (offset -4): difficulty 10 → 6 characters. Solution is HMAC-encrypted in the challenge store — never stored in plaintext. Works without JavaScript. Requires `Pillow`:

```bash
pip install tollbooth[image]
```

#### Setup

```python
from tollbooth import CharacterCaptcha, TollboothWSGI

app = TollboothWSGI(
    app,
    secret="your-secret-key",          # also used to sign CAPTCHA solution tokens
    challenge_handler=CharacterCaptcha(
        backgrounds_path="/path/to/backgrounds", # optional directory of .jpg files
        token_ttl=1800,                          # solution token lifetime in seconds
    ),
)
```

System fonts are detected automatically from common OS directories. Only fonts from known Latin families (DejaVu, Fira, Liberation, Ubuntu, etc.) are used. Background images are optional — falls back to a solid fill.

### Sliding CAPTCHA

Human-solved drag-and-drop challenge. Renders a decorative background (wavy lines, concentric circles, 3D wireframe shapes, noise) then cuts out a rectangular puzzle piece, leaving a dark outlined hole. The user slides the piece to fill the hole using an `<input type="range">`. The correct position is HMAC-encrypted in the challenge token — never stored in plaintext. Verification accepts ±15 px tolerance (tightens by 1 px per difficulty level, minimum 5 px). Requires `Pillow`:

```bash
pip install tollbooth[image]
```

#### Setup

```python
from tollbooth import SlidingCaptcha, TollboothWSGI

app = TollboothWSGI(
    app,
    secret="your-secret-key",
    challenge_handler=SlidingCaptcha(
        token_ttl=1800,  # solution token lifetime in seconds
    ),
)
```

### Circle CAPTCHA

Human-solved click challenge. Renders an image containing several complete circles and one with a visible gap in its arc. The user clicks the incomplete circle — click coordinates are captured and submitted automatically. The correct circle's center and radius are HMAC-encrypted in the challenge token. Verification accepts clicks within `radius + 15 px` of the target circle's center. Difficulty controls the number of circles (`max(3, 2 + d//2)`) and gap arc size (`max(25°, 50° - 2d)`). Requires `Pillow`:

```bash
pip install tollbooth[image]
```

#### Setup

```python
from tollbooth import CircleCaptcha, TollboothWSGI

app = TollboothWSGI(
    app,
    secret="your-secret-key",
    challenge_handler=CircleCaptcha(
        token_ttl=1800,
    ),
)
```

### Third-party CAPTCHA challenge

`ThirdPartyCaptchaChallenge` integrates any supported third-party CAPTCHA provider directly into tollbooth's own challenge engine. The user is redirected to a tollbooth-hosted page that renders the CAPTCHA widget; on completion the widget token is submitted and verified server-side before issuing the access cookie.

**Supported providers:** `recaptcha`, `hcaptcha`, `turnstile`, `friendly`, `captchafox`, `mtcaptcha`, `arkose`, `geetest`, `altcha`

The page retries on failure (`retry_on_failure = True`). Difficulty does not affect the external verification logic; the offset is `0`.

#### Setup

```python
from tollbooth import ThirdPartyCaptchaChallenge, CaptchaCreds, AltchaCreds, TollboothWSGI

# Standard provider (reCAPTCHA, hCaptcha, Turnstile, …)
app = TollboothWSGI(
    app,
    secret="your-secret-key",
    challenge_handler=ThirdPartyCaptchaChallenge(
        provider="recaptcha",
        creds=CaptchaCreds(
            site_key="6Le...",
            secret_key="6Le...",
        ),
        language="en",   # optional, default "auto"
        theme="auto",    # "light" | "dark" | "auto"
    ),
)

# GeeTest v4
challenge_handler=ThirdPartyCaptchaChallenge(
    provider="geetest",
    creds=CaptchaCreds(site_key="...", secret_key="..."),
)

# Altcha (self-hosted, no site key)
challenge_handler=ThirdPartyCaptchaChallenge(
    provider="altcha",
    creds=AltchaCreds(secret_key="your-altcha-secret"),
)
```

The credential type aliases `ReCaptchaCreds`, `HCaptchaCreds`, `TurnstileCreds`, `FriendlyCaptchaCreds`, `CaptchaFoxCreds`, `MTCaptchaCreds`, `ArkoseCreds`, `GeeTestCreds` are all aliases for `CaptchaCreds`.

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

Flask and Django integrations pull `secret` from the framework's built-in secret key (`SECRET_KEY`). All options below can also be set via Flask's `app.config["TOLLBOOTH_<UPPER_NAME>"]` or Django's `TOLLBOOTH = {...}` dict.

```python
from tollbooth import SHA256Balloon, TollboothWSGI

TollboothWSGI(
    app,
    secret="your-secret-key",         # required for WSGI/ASGI/Falcon
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
    accent_color="#44ff88",            # theme accent color (default: "#44ff88")
    max_challenge_failures=3,          # failed verifies before 429 lockout (default: 3)
    max_challenge_requests=10,         # challenge generations before 429 lockout (default: 10)
    rate_limit_window=300,             # sliding window for both limits in seconds (default: 300)
    token_rate_limit=120,              # max requests per token per rate window (default: 120)
    token_rate_window=60,              # rate window duration in seconds (default: 60)
    token_total_limit=3000,            # max lifetime requests per token (default: 3000)
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

Tollbooth ships with [rules.json](https://github.com/libcaptcha/tollbooth/blob/main/tollbooth/rules.json) covering common traffic patterns out of the box:

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

All framework integrations accept the same keyword arguments as `TollboothWSGI`/`TollboothASGI`. Flask and Django use the framework's `SECRET_KEY` by default — no separate secret needed.

| Integration   | Import                             | Middleware class      | Per-route            | Exempt              | Auto secret  |
| ------------- | ---------------------------------- | --------------------- | -------------------- | ------------------- | ------------ |
| **Flask**     | `tollbooth.integrations.flask`     | `Tollbooth(app)`      | `@tb.protect`        | `@tb.exempt`        | `SECRET_KEY` |
| **Django**    | `tollbooth.integrations.django`    | `TollboothMiddleware` | `@tollbooth_protect` | `@tollbooth_exempt` | `SECRET_KEY` |
| **FastAPI**   | `tollbooth.integrations.fastapi`   | `TollboothMiddleware` | `TollboothDep`       | `exclude=[...]`     | —            |
| **Falcon**    | `tollbooth.integrations.falcon`    | `TollboothMiddleware` | `tollbooth_hook`     | `exclude=[...]`     | —            |
| **Starlette** | `tollbooth.integrations.starlette` | `TollboothMiddleware` | —                    | `exclude=[...]`     | —            |
| **WSGI**      | `tollbooth`                        | `TollboothWSGI`       | —                    | —                   | —            |
| **ASGI**      | `tollbooth`                        | `TollboothASGI`       | —                    | —                   | —            |

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

## Reading claims

When a request passes (valid cookie, allow rule, or after solving a challenge), each integration exposes a claims object on the native request object — no manual cookie decoding needed.

| Integration   | Claims location               |
| ------------- | ----------------------------- |
| **Flask**     | `flask.g.tollbooth`           |
| **Django**    | `request.tollbooth`           |
| **FastAPI**   | `request.state.tollbooth`     |
| **Starlette** | `request.state.tollbooth`     |
| **Falcon**    | `req.context.tollbooth`       |
| **WSGI**      | `environ["tollbooth.claims"]` |
| **ASGI**      | `scope["state"].tollbooth`    |

| Field             | Type            | Description                                                                          |
| ----------------- | --------------- | ------------------------------------------------------------------------------------ |
| `score`           | `float \| None` | Attestation score 0.0–1.0; `None` for PoW challenges                                 |
| `iat`             | `int`           | Issued-at timestamp                                                                  |
| `exp`             | `int`           | Expiry timestamp                                                                     |
| `ip`              | `str`           | HMAC of the client IP                                                                |
| `cid`             | `str`           | Challenge ID                                                                         |
| `matched_rule`    | `str \| None`   | Name of the `deny` or `challenge` rule that matched; `None` for allow / weight-based |
| `blocklist_match` | `str \| None`   | IP range from the blocklist (e.g. `"1.2.0.0/16"`) when a blocklist rule matched      |
| `is_crawler`      | `bool`          | `True` if the user-agent is a known crawler (requires `crawleruseragents`)           |
| `crawler_name`    | `str \| None`   | Crawler product name when `is_crawler` is `True`                                     |

```python
# Flask
claims = g.tollbooth

# Django
claims = request.tollbooth

# FastAPI / Starlette
claims = request.state.tollbooth

# Falcon
claims = req.context.tollbooth

# WSGI
claims = environ["tollbooth.claims"]

print(claims.matched_rule, claims.is_crawler, claims.crawler_name)
```

`is_crawler` and `crawler_name` require the optional `crawleruseragents` package:

```bash
pip install crawleruseragents
```

## IP Blocklist

Challenge or block known malicious IPs using [tn3w/IPBlocklist](https://github.com/tn3w/IPBlocklist). Supports single IPs, CIDR ranges, and IP ranges for IPv4 and IPv6.

### In-memory

```python
from tollbooth import Engine, IPBlocklist

# Single source — cached at ~/.cache/tollbooth/<filename>
blocklist = IPBlocklist()        # defaults to tn3w/IPBlocklist
blocklist.load()                 # downloads once; uses cache on subsequent calls
blocklist.load(force=True)       # bypass cache and re-download

# Multiple sources
blocklists = IPBlocklist.from_sources([
    "https://example.com/list1.txt",
    "https://example.com/list2.txt",
])
for bl in blocklists:
    bl.load()

engine = Engine("your-secret-key", blocklist=blocklist)   # or blocklist=blocklists
blocklist.start_updates(interval=86400)  # daily refresh; clears cache before re-downloading
```

Parsed into compact integer ranges with O(log n) binary search. No dependencies.
The `blocklist` kwarg accepts a single `IPBlocklist` or a `list[IPBlocklist]`; an IP is blocked if it matches any.

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

Share challenges, secret, config, rules, and rate-limit counters across workers via Redis (or Dragonfly, KeyDB, Valkey).

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
              │ rate limits│
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

## Third-party CAPTCHAs

`ThirdPartyCaptcha` in `tollbooth.extras.third_party_captcha` embeds and validates third-party CAPTCHA providers across all supported frameworks. It is independent of tollbooth's own challenge engine.

To use a third-party CAPTCHA as a tollbooth challenge type instead (redirect-based, engine-managed), see [`ThirdPartyCaptchaChallenge`](#third-party-captcha-challenge).

**Supported providers:** `recaptcha`, `hcaptcha`, `turnstile`, `friendly`, `captchafox`, `mtcaptcha`, `arkose`, `geetest`, `altcha`

```python
from tollbooth.extras.third_party_captcha import ThirdPartyCaptcha

captcha = ThirdPartyCaptcha(
    language="en",
    theme="auto",                        # "light" | "dark" | "auto"
    recaptcha_site_key="...",
    recaptcha_secret="...",
    hcaptcha_site_key="...",
    hcaptcha_secret="...",
    turnstile_site_key="...",
    turnstile_secret="...",
    friendly_site_key="...",
    friendly_secret="...",
    captchafox_site_key="...",
    captchafox_secret="...",
    mtcaptcha_site_key="...",
    mtcaptcha_secret="...",
    arkose_site_key="...",
    arkose_secret="...",
    geetest_site_key="...",
    geetest_secret="...",
    altcha_secret="...",                 # self-hosted, no site key needed
)
```

`get_context()` returns all configured providers as a dict of pre-escaped HTML strings. `get_embed(provider)` returns HTML for a single provider.

### Flask

```python
captcha.init_flask(app)   # injects all providers into every template context

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST" and captcha.is_recaptcha_valid():
        ...
    return render_template("login.html")  # {{ recaptcha }} in template
```

### Django

```python
# settings.py
TEMPLATES[0]["OPTIONS"]["context_processors"].append(
    captcha.as_django_context_processor()
)

# views.py
def login(request):
    if request.method == "POST" and captcha.is_recaptcha_valid(request):
        ...
    return render(request, "login.html")  # {{ recaptcha }} in template
```

### Falcon

```python
class LoginResource:
    def on_post(self, req, resp):
        if not captcha.is_recaptcha_valid(req):
            raise falcon.HTTPForbidden()
```

### FastAPI / Starlette

```python
from fastapi import Request

@app.post("/login")
async def login(request: Request):
    if not await captcha.is_recaptcha_valid_async(request):
        raise HTTPException(status_code=403)
```

For template rendering, pass `captcha.get_context()` directly to `TemplateResponse`:

```python
return templates.TemplateResponse(
    "login.html",
    {"request": request, **captcha.get_context()},
)
```

### Altcha (self-hosted)

Altcha generates and verifies challenges server-side — no third-party account needed:

```python
captcha = ThirdPartyCaptcha(altcha_secret="your-secret")

# In templates: {{ altcha }}, {{ altcha2 }}, … {{ altcha5 }} (hardness 1–5)
# Validate:
captcha.is_altcha_valid()               # Flask
captcha.is_altcha_valid(request)        # Django / Falcon
await captcha.is_altcha_valid_async(request)  # FastAPI / Starlette
```

### GeeTest v4

GeeTest requires four hidden fields populated by the JS callback (`geetest_lotNumber`, `geetest_captchaOutput`, `geetest_passToken`, `geetest_genTime`). The embed handles this automatically; verification is HMAC-signed server-side.

### Arkose Labs

The embed loads Arkose's enforcement script dynamically, using the site key as the script path segment. The completed token is written to a hidden `fc-token` field.

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

## Contributing

We welcome contributions of all kinds — bug reports, feature requests, docs improvements, and code changes. See [CONTRIBUTING.md](https://github.com/libcaptcha/tollbooth/blob/main/CONTRIBUTING.md) for guidelines.

**Quick links:**

- [Open an issue](https://github.com/libcaptcha/tollbooth/issues/new) — bug reports, feature ideas, questions
- [Browse open issues](https://github.com/libcaptcha/tollbooth/issues) — find something to work on
- [Good first issues](https://github.com/libcaptcha/tollbooth/labels/good%20first%20issue) — great starting points for new contributors

```bash
git clone https://github.com/libcaptcha/tollbooth.git
cd tollbooth
pip install -e ".[test,flask,django,fastapi,falcon,starlette,redis,image]"
pytest tests/ -v
```

Please read our [Code of Conduct](https://github.com/libcaptcha/tollbooth/blob/main/CODE_OF_CONDUCT.md) before participating.

## Security

To report a vulnerability, **do not open a public issue**. See [SECURITY.md](https://github.com/libcaptcha/tollbooth/blob/main/SECURITY.md) for responsible disclosure instructions.

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

[MIT](https://github.com/libcaptcha/tollbooth/blob/main/LICENSE)
