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

    # URL depth (M2)
    sandbox_url: str = "http://sandbox:8100"
    sandbox_enabled: bool = True
    rdap_base: str = "https://rdap.org"
    webrisk_api_key: SecretStr = SecretStr("")
    deep_check_budget_seconds: float = 15.0
    max_deep_urls: int = 3
    # Send a screenshot of the fake page as an image with the verdict as its caption
    # (still ONE message). Only when the caption fits WhatsApp's 1024-char limit.
    send_screenshots: bool = True

    # Images (M3)
    max_image_bytes: int = 5 * 1024 * 1024  # WhatsApp image limit
    ocr_langs: str = "hin+eng"
    ocr_timeout_seconds: float = 15.0

    # APK files (M4): parsed statically in the sandbox, never installed or run
    max_apk_bytes: int = 60 * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
