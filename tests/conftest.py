import fakeredis
import pytest
from pydantic import SecretStr

from kavach.config import Settings
from tests.fakes import FakeMessenger, FakeStore

APP_SECRET = "test-app-secret"
VERIFY_TOKEN = "test-verify-token"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        meta_app_secret=SecretStr(APP_SECRET),
        whatsapp_verify_token=SecretStr(VERIFY_TOKEN),
        whatsapp_access_token=SecretStr("token"),
        whatsapp_phone_number_id="123",
        user_hash_key=SecretStr("k" * 64),
        rate_limit_per_hour=5,
        _env_file=None,  # type: ignore[call-arg]
    )


@pytest.fixture
async def redis():  # type: ignore[no-untyped-def]
    r = fakeredis.FakeAsyncRedis()
    yield r
    await r.aclose()


@pytest.fixture
def store() -> FakeStore:
    return FakeStore()


@pytest.fixture
def messenger() -> FakeMessenger:
    return FakeMessenger()


def webhook_payload(
    text: str = "",
    *,
    msg_id: str = "wamid.1",
    wa_id: str = "919800000001",
    mtype: str = "text",
    extra: dict | None = None,
) -> dict:  # type: ignore[type-arg]
    msg: dict = {"from": wa_id, "id": msg_id, "timestamp": "1760000000", "type": mtype}  # type: ignore[type-arg]
    if mtype == "text":
        msg["text"] = {"body": text}
    if extra:
        msg.update(extra)
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "WABA",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "15550000000",
                                "phone_number_id": "123",
                            },
                            "contacts": [{"profile": {"name": "Kamla"}, "wa_id": wa_id}],
                            "messages": [msg],
                        },
                    }
                ],
            }
        ],
    }
