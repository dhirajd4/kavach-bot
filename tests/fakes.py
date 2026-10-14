from dataclasses import dataclass, field

from kavach.reputation.memory import MemoryStore

FakeStore = MemoryStore


@dataclass
class FakeMessenger:
    sent: list[tuple[str, str, str | None]] = field(default_factory=list)
    read: list[str] = field(default_factory=list)

    async def send_text(self, to: str, body: str, reply_to: str | None = None) -> None:
        self.sent.append((to, body, reply_to))

    async def mark_read(self, message_id: str, typing: bool = True) -> None:
        self.read.append(message_id)
