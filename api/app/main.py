from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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


# Replace the default Pydantic 422 response with a single-line generic
# "invalid request" string. The default body exposes Pydantic loc/type
# internals + the offending input value, which audit v3 (L2) flagged
# as a framework-fingerprinting + reflected-input leak.
@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(
    request: Request, exc: RequestValidationError
):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "invalid request"},
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
        # Invite-code gating retired — left in the response as `false`
        # so older bundles still receive the key.
        "invite_required": False,
        "onion_address": _read_onion_address(),
    }


_v1 = "/api/v1"
app.include_router(auth.router, prefix=_v1)
app.include_router(users.router, prefix=_v1)
app.include_router(mail.router, prefix=_v1)
app.include_router(abuse.router, prefix=_v1)
app.include_router(internal.router, prefix=_v1)
app.include_router(admin.router, prefix=_v1)
