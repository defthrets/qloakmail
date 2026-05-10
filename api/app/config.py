from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    voidmail_domain: str = "voidmail.local"
    voidmail_hostname: str = "mx.voidmail.local"
    voidmail_extra_domains: str = ""

    postgres_user: str
    postgres_password: str
    postgres_db: str
    postgres_host: str = "postgres"
    postgres_port: int = 5432

    redis_host: str = "redis"
    redis_port: int = 6379

    api_secret_key: str
    invite_codes: str = ""
    captcha_provider: str = "none"
    captcha_secret: str = ""

    internal_api_token: str

    # Comma-separated list of email addresses that get admin access
    # to /api/v1/admin/*. Set in .env, never committed. An empty list
    # means admin endpoints are completely disabled.
    admin_emails: str = ""

    # Public registration. When false (default), POST /auth/register
    # returns 403 — accounts must be provisioned out-of-band by an
    # admin. The webmail no longer surfaces a signup form regardless;
    # this flag is the server-side enforcement.
    registration_enabled: bool = False

    # HMAC secret used to fingerprint banned IPs. Persisted (unlike
    # the per-process rate-limit secret) so a banned IP stays banned
    # across restarts. Treat like a private key — change it and all
    # existing IP bans become useless. Defaults to a derivative of
    # the api secret if not set so deployments don't have to add a
    # second secret.
    ip_ban_secret: str = ""

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/0"

    @property
    def all_domains(self) -> list[str]:
        domains = [self.voidmail_domain]
        if self.voidmail_extra_domains:
            domains += [d.strip() for d in self.voidmail_extra_domains.split(",") if d.strip()]
        return domains

    @property
    def invite_code_set(self) -> set[str]:
        return {c.strip() for c in self.invite_codes.split(",") if c.strip()}

    @property
    def admin_email_set(self) -> set[str]:
        return {e.strip().lower() for e in self.admin_emails.split(",") if e.strip()}

    @property
    def effective_ip_ban_secret(self) -> str:
        # Falls back to a deterministic derivative of api_secret_key so
        # operators don't have to set a second secret unless they want
        # IP bans to survive an api_secret_key rotation.
        return self.ip_ban_secret or (self.api_secret_key + ".ipban")


@lru_cache
def get_settings() -> Settings:
    return Settings()
