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


@lru_cache
def get_settings() -> Settings:
    return Settings()
