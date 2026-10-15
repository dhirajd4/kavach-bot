from dataclasses import dataclass, field

from kavach.reputation.memory import MemoryStore

FakeStore = MemoryStore


@dataclass
class FakeMessenger:
    sent: list[tuple[str, str, str | None]] = field(default_factory=list)
    read: list[str] = field(default_factory=list)
    images: list[tuple[str, bytes, str, str | None]] = field(default_factory=list)
    media: dict[str, bytes] = field(default_factory=dict)

    async def send_text(self, to: str, body: str, reply_to: str | None = None) -> None:
        self.sent.append((to, body, reply_to))

    async def mark_read(self, message_id: str, typing: bool = True) -> None:
        self.read.append(message_id)

    async def send_image(
        self, to: str, image: bytes, caption: str, reply_to: str | None = None
    ) -> None:
        self.images.append((to, image, caption, reply_to))

    async def download_media(self, media_id: str, max_bytes: int) -> bytes:
        if len(self.media[media_id]) > max_bytes:
            raise ValueError("media too large")
        return self.media[media_id]
