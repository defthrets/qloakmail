from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .routes import abuse, auth, internal, mail, users


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
    }


_v1 = "/api/v1"
app.include_router(auth.router, prefix=_v1)
app.include_router(users.router, prefix=_v1)
app.include_router(mail.router, prefix=_v1)
app.include_router(abuse.router, prefix=_v1)
app.include_router(internal.router, prefix=_v1)
