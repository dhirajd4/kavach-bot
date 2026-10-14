"""Runtime settings. Every secret comes from the environment (.env locally)."""

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Meta WhatsApp Cloud API
    whatsapp_access_token: SecretStr = SecretStr("")
    whatsapp_phone_number_id: str = ""
    whatsapp_waba_id: str = ""
    meta_app_secret: SecretStr = SecretStr("")
    whatsapp_verify_token: SecretStr = SecretStr("")
    graph_api_version: str = "v23.0"
    graph_api_base: str = "https://graph.facebook.com"
    # True: never call Meta; replies are parked in Redis for the replay tool.
    whatsapp_dry_run: bool = False

    # Privacy
    user_hash_key: SecretStr = SecretStr("")

    # Infra
    database_url: str = "postgresql+asyncpg://kavach:kavach@localhost:5432/kavach"
    redis_url: str = "redis://localhost:6379/0"

    # Behaviour
    rate_limit_per_hour: int = 20
    reply_cache_ttl_seconds: int = 6 * 3600
    idempotency_ttl_seconds: int = 24 * 3600
    openphish_feed_url: str = "https://openphish.com/feed.txt"
    openphish_sync_seconds: int = 3600
    http_timeout_seconds: float = 8.0
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
