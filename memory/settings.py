"""Environment-backed factories for the two memory architectures."""

import os
from pathlib import Path

from memory.agent_memory import AgentMemoryService, CogneeMemory, ExecutionStore, FileArtifactStore
from memory.chat_memory import ChatMemoryService, ObsidianVault
from memory.redis_store import RedisWorkingMemory

# Resolve the project root once so relative paths in .env work regardless of
# which directory the process is launched from.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _resolve(env_var: str, default: str) -> Path:
    """Return an absolute path, resolving relative values against the project root."""
    raw = os.environ.get(env_var, default)
    p = Path(raw)
    return p if p.is_absolute() else (_PROJECT_ROOT / p).resolve()


def build_chat_memory() -> ChatMemoryService:
    """Chat memory = Redis context window + Obsidian Markdown vault.

    The Obsidian vault is the 'MCP Memory' folder at the project root which
    already contains the .obsidian configuration created when you opened it
    in the Obsidian desktop app.
    """
    working = RedisWorkingMemory(
        os.environ.get("MEMORY_REDIS_URL", "redis://127.0.0.1:6379/0"),
        namespace="llm-chat",
        ttl_seconds=int(os.environ.get("CHAT_MEMORY_REDIS_TTL_SECONDS", "3600")),
    )
    vault_path = _resolve("OBSIDIAN_VAULT_PATH", "./MCP Memory")
    return ChatMemoryService(working, ObsidianVault(vault_path))


def build_agent_memory() -> AgentMemoryService:
    """Agent memory = Redis working state + Cognee semantic graph + SQLite + artifacts."""
    working = RedisWorkingMemory(
        os.environ.get("MEMORY_REDIS_URL", "redis://127.0.0.1:6379/0"),
        namespace="ai-agent",
    )
    return AgentMemoryService(
        working,
        CogneeMemory(enabled=_bool("AGENT_MEMORY_COGNEE_ENABLED", True)),
        ExecutionStore(_resolve("AGENT_EXECUTION_DB_PATH", "./memory-data/executions.sqlite3")),
        FileArtifactStore(_resolve("AGENT_ARTIFACT_ROOT", "./memory-data/artifacts")),
    )
