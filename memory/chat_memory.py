"""Chat memory: Redis context window plus durable Obsidian Markdown notes."""

import datetime as dt
import json
import re
from pathlib import Path

from memory.redis_store import RedisWorkingMemory


class ObsidianVault:
    """Append-only, human-readable conversation knowledge in an Obsidian vault."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    @staticmethod
    def _safe_id(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", value)

    def append_turn(self, conversation_id: str, role: str, content: str, *, metadata: dict | None = None) -> Path:
        if role not in {"user", "assistant", "system"}:
            raise ValueError("role must be user, assistant, or system")
        day = dt.datetime.now(dt.timezone.utc).date().isoformat()
        path = self.root / "Chats" / f"{day}-{self._safe_id(conversation_id)}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(
                "---\n"
                f"conversation_id: {json.dumps(conversation_id)}\n"
                f"created_at: {dt.datetime.now(dt.timezone.utc).isoformat()}\n"
                "memory_type: long_term_chat\n---\n\n",
                encoding="utf-8",
            )
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        details = f"\nMetadata: `{json.dumps(metadata, sort_keys=True)}`" if metadata else ""
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"## {timestamp} — {role}\n\n{content}{details}\n\n")
        return path

    def write_fact(self, title: str, content: str, *, tags: list[str] | None = None) -> Path:
        path = self.root / "Knowledge" / f"{self._safe_id(title)}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        frontmatter = (
            f"tags: {json.dumps(tags or [])}\n"
            f"updated_at: {dt.datetime.now(dt.timezone.utc).isoformat()}"
        )
        path.write_text(f"---\n{frontmatter}\n---\n\n# {title}\n\n{content}\n", encoding="utf-8")
        return path


class ChatMemoryService:
    """Separates expiring LLM context from durable, reviewable knowledge."""

    def __init__(self, working_memory: RedisWorkingMemory, vault: ObsidianVault, context_limit: int = 30):
        self.working_memory = working_memory
        self.vault = vault
        self.context_limit = context_limit

    async def add_turn(self, conversation_id: str, role: str, content: str, *, trace_id: str | None = None) -> Path:
        event = {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), "role": role, "content": content, "trace_id": trace_id}
        await self.working_memory.append_event("chat", conversation_id, event, self.context_limit)
        return self.vault.append_turn(conversation_id, role, content, metadata={"trace_id": trace_id} if trace_id else None)

    async def context(self, conversation_id: str) -> list[dict]:
        return await self.working_memory.get_events("chat", conversation_id)
