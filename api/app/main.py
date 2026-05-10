from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .routes import abuse, admin, auth, internal, mail, users

# Tor publishes the hidden-service hostname here once it bootstraps.
# Volume is mounted read-only via docker-compose. We re-read on each
# /config call so the SPA picks it up as soon as Tor is ready, and any
# future rotation (rare — keys persist in tor-keys volume) shows up
# automatically.
_ONION_HOSTNAME_FILE = Path("/var/lib/tor/voidmail/hostname")


def _read_onion_address() -> str:
    try:
        return _ONION_HOSTNAME_FILE.read_text().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


settings = get_settings()

app = FastAPI(
    title="QloakMail API",
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# In dev, the SPA is served from the same nginx host so CORS is not strictly
# required. Allowing localhost makes direct API testing painless.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:8080",
        "https://" + settings.voidmail_domain,
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health", tags=["meta"])
async def health():
    return {"status": "ok"}


@app.get("/api/v1/config", tags=["meta"])
async def public_config():
    """Config the SPA needs at boot — no secrets."""
    return {
        "domain": settings.voidmail_domain,
        "domains": settings.all_domains,
        "captcha_provider": settings.captcha_provider,
        "invite_required": bool(settings.invite_code_set),
        "onion_address": _read_onion_address(),
    }


_v1 = "/api/v1"
app.include_router(auth.router, prefix=_v1)
app.include_router(users.router, prefix=_v1)
app.include_router(mail.router, prefix=_v1)
app.include_router(abuse.router, prefix=_v1)
app.include_router(internal.router, prefix=_v1)
app.include_router(admin.router, prefix=_v1)
