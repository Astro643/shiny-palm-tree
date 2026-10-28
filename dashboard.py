"""Security dashboard (Render web service).
Start:  uvicorn dashboard:app --host 0.0.0.0 --port $PORT
Env:    DASHBOARD_PASSWORD, SESSION_SECRET (optional), UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
Deps:   fastapi, uvicorn[standard], upstash-redis
"""
import asyncio, hashlib, hmac, json, os, uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from upstash_redis.asyncio import Redis

PASSWORD = os.environ["DASHBOARD_PASSWORD"]
SECRET = os.environ.get("SESSION_SECRET", PASSWORD).encode()
HTML = (Path(__file__).parent / "templates" / "dashboard.html").read_text(encoding="utf-8")
MAX_QUEUE = 25
STATES = {"processing", "executed", "blocked_by_traffic", "failed_sensibility", "failed"}


@asynccontextmanager
async def lifespan(app: FastAPI):  # startup / shutdown
    app.state.r = Redis.from_env()
    yield
    try:
        await app.state.r.close()
    except Exception:
        pass


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


class Login(BaseModel):
    guild_id: str
    password: str


class Cmd(BaseModel):
    prompt: str = Field(min_length=1, max_length=500)


@app.exception_handler(Exception)
async def _redis_down(_, __):
    return JSONResponse({"detail": "Couldn't reach the database. Try again in a moment."}, 502)


def _sig(g: str) -> str:
    return hmac.new(SECRET, g.encode(), hashlib.sha256).hexdigest()


def guild(req: Request) -> str:
    """Verify the signed session cookie ('<guild_id>.<hmac>') and return the guild id."""
    g, _, s = req.cookies.get("session", "").partition(".")
    if g.isdigit() and hmac.compare_digest(s.encode(), _sig(g).encode()):
        return g
    raise HTTPException(401, "Sign in to continue.")


def _j(v):
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return v


async def load_config(r: Redis, g: str):
    """Read guild:{id}:config, stored either as a JSON string or as a hash of JSON values."""
    k = f"guild:{g}:config"
    try:
        raw = await r.get(k)
    except Exception:  # WRONGTYPE -> it's a hash
        h = await r.hgetall(k)
        raw = {f: _j(v) for f, v in h.items()} if h else None
    raw = _j(raw) if isinstance(raw, str) else raw
    if not isinstance(raw, dict):
        return None
    for f in ("quarantine_role_id", "log_channel_id", "verify_channel_id"):  # keep snowflakes exact in JS
        if raw.get(f) is not None:
            raw[f] = str(raw[f])
    w = raw.get("whitelist")
    raw["whitelist"] = len(w) if isinstance(w, (list, dict, str)) else 0  # send depth only, not identities
    return raw


def suggest(c: dict) -> list:
    """Floating pills derived from gaps in the live configuration."""
    m = lambda k: c.get(k) or {}
    out = []
    if m("panic").get("active"):
        out.append(("🟢 Lift Panic Mode", "Lift panic mode and restore normal operation"))
    if not c.get("whitelist"):
        out.append(("🔒 Configure Whitelist", "Configure the whitelist: add the server owner and trusted admins"))
    if not set(m("panic")) - {"active"}:
        out.append(("🚨 Arm Panic Mode", "Arm panic mode with sensible emergency freeze thresholds"))
    if not m("joingate").get("enabled"):
        out.append(("🛡️ Enable JoinGate", "Enable JoinGate with captcha verification"))
    if not m("antinuke").get("enabled"):
        out.append(("☢️ Enable Anti-Nuke", "Enable the anti-nuke watchdog with default limits"))
    if not m("automod").get("enabled"):
        out.append(("🤖 Enable AutoMod", "Enable AutoMod with spam, link and mass-mention filters"))
    if not c.get("log_channel_id"):
        out.append(("📜 Set Log Channel", "Set the security log channel"))
    if not c.get("quarantine_role_id"):
        out.append(("🧯 Set Quarantine Role", "Set the quarantine role for flagged members"))
    return [{"label": a, "prompt": b} for a, b in out[:6]]


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML


@app.get("/healthz")
async def health():
    return {"ok": True}


@app.post("/api/login")
async def login(b: Login, req: Request, res: Response):
    g = b.guild_id.strip()
    if not (g.isdigit() and 15 <= len(g) <= 22 and hmac.compare_digest(b.password.encode(), PASSWORD.encode())):
        raise HTTPException(401, "Check the server ID and password.")
    https = req.headers.get("x-forwarded-proto", req.url.scheme) == "https"
    res.set_cookie("session", f"{g}.{_sig(g)}", max_age=7 * 86400, httponly=True, samesite="lax", secure=https)
    return {"ok": True}


@app.post("/api/logout")
async def logout(res: Response):
    res.delete_cookie("session")
    return {"ok": True}


@app.get("/api/config")
async def get_config(req: Request):
    g = guild(req)
    c = await load_config(req.app.state.r, g)
    return {"guild_id": g, "exists": c is not None, "config": c or {}, "suggestions": suggest(c or {})}


@app.post("/api/command")
async def command(b: Cmd, req: Request):
    g, r = guild(req), req.app.state.r
    p, q = b.prompt.strip(), f"guild:{g}:command_queue"
    if not p:
        raise HTTPException(422, "Enter a command first.")
    if await r.llen(q) >= MAX_QUEUE:
        raise HTTPException(429, f"The worker queue is full ({MAX_QUEUE}/{MAX_QUEUE}). Try again in a moment.")
    cid = str(uuid.uuid4())
    await r.lpush(q, json.dumps({"command_id": cid, "prompt_input": p}))
    return {"command_id": cid}


@app.get("/api/status/{command_id}")
async def status(command_id: str, req: Request):
    """Long-poll (~15s): returns as soon as the worker leaves `processing`."""
    guild(req)
    try:
        cid = str(uuid.UUID(command_id))
    except ValueError:
        raise HTTPException(400, "Invalid command ID.")
    r, s = req.app.state.r, "processing"
    for _ in range(15):
        v = await r.get(f"command:{cid}:status")
        s = v if v in STATES else "processing"
        if s != "processing":
            break
        await asyncio.sleep(1)
    out = {"status": s}
    if s in ("failed", "failed_sensibility", "blocked_by_traffic"):
        out["error"] = await r.get(f"command:{cid}:error")
    return out
