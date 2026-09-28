"""Agent memory: Redis working state, Cognee semantic memory, SQL records, artifacts."""
# cognee 1.6.1 API: remember(text, dataset_name=...) / recall(query, dataset_name=...)

import datetime as dt
import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Protocol

from memory.redis_store import RedisWorkingMemory


class CogneeBackend(Protocol):
    async def remember(self, text: str, dataset: str) -> None: ...
    async def recall(self, query: str, dataset: str) -> Any: ...


class CogneeMemory:
    """Adapter for Cognee 1.6.1 semantic/episodic graph memory; no silent fallback.

    Uses cognee.remember(text, dataset_name=...) to store and
    cognee.recall(query, dataset_name=...) to retrieve memories.
    A disabled or missing Cognee installation is explicit — the agent will
    never silently assume it has durable semantic memory when it does not.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._configured = False

    def _ensure_configured(self) -> None:
        """Lazily configure Cognee on the first call (idempotent)."""
        if self._configured:
            return
        from memory.cognee_setup import configure_cognee  # local import avoids circular deps
        configure_cognee()
        self._configured = True

    @staticmethod
    async def _await_if_needed(value):
        import inspect
        if inspect.isawaitable(value):
            return await value
        return value

    async def remember(self, text: str, dataset: str) -> None:
        """Store *text* in Cognee under *dataset* (agent name)."""
        if not self.enabled:
            return
        try:
            import cognee
        except ImportError as exc:
            raise RuntimeError(
                "Cognee long-term memory is enabled but `cognee` is not installed. "
                "Run: pip install cognee"
            ) from exc
        self._ensure_configured()
        # cognee 1.6.1: remember(text, dataset_name=...) — positional first arg is the text
        result = cognee.remember(text, dataset_name=dataset)
        await self._await_if_needed(result)

    async def recall(self, query: str, dataset: str) -> Any:
        """Retrieve memories related to *query* from *dataset*."""
        if not self.enabled:
            return []
        try:
            import cognee
        except ImportError as exc:
            raise RuntimeError(
                "Cognee long-term memory is enabled but `cognee` is not installed. "
                "Run: pip install cognee"
            ) from exc
        self._ensure_configured()
        # cognee 1.6.1: recall(query, dataset_name=...) — positional first arg is the query
        result = cognee.recall(query, dataset_name=dataset)
        return await self._await_if_needed(result)


class FileArtifactStore:
    """Content-addressed JSON artifact store; replace with S3/MinIO behind this API."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def put_json(self, payload: Any) -> dict:
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        path = self.root / digest[:2] / f"{digest}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(encoded)
        return {"uri": path.resolve().as_uri(), "sha256": digest, "bytes": len(encoded)}


class ExecutionStore:
    """Durable structured execution/event store (SQLite, a PostgreSQL equivalent)."""

    def __init__(self, database_path: str | Path):
        path = Path(database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS agent_runs (
                run_id TEXT PRIMARY KEY, trace_id TEXT NOT NULL, agent_name TEXT NOT NULL,
                status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, metadata_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS execution_events (
                event_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL, tool_name TEXT, status TEXT NOT NULL,
                artifact_uri TEXT, details_json TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES agent_runs(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_runs_trace ON agent_runs(trace_id);
            CREATE INDEX IF NOT EXISTS idx_events_run ON execution_events(run_id, timestamp);
        """)
        self.connection.commit()

    def start_run(self, trace_id: str, agent_name: str, metadata: dict | None = None) -> str:
        run_id = str(uuid.uuid4())
        self.connection.execute(
            "INSERT INTO agent_runs VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, trace_id, agent_name, "running", dt.datetime.now(dt.timezone.utc).isoformat(), None, json.dumps(metadata or {})),
        )
        self.connection.commit()
        return run_id

    def record_event(self, run_id: str, event_type: str, status: str, *, tool_name: str | None = None, artifact_uri: str | None = None, details: dict | None = None) -> None:
        self.connection.execute(
            "INSERT INTO execution_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), run_id, dt.datetime.now(dt.timezone.utc).isoformat(), event_type, tool_name, status, artifact_uri, json.dumps(details or {}, default=str)),
        )
        self.connection.commit()

    def finish_run(self, run_id: str, status: str) -> None:
        self.connection.execute("UPDATE agent_runs SET status=?, finished_at=? WHERE run_id=?", (status, dt.datetime.now(dt.timezone.utc).isoformat(), run_id))
        self.connection.commit()

    def timeline(self, trace_id: str) -> list[dict]:
        rows = self.connection.execute("""
            SELECT r.run_id, r.agent_name, r.status AS run_status, e.timestamp, e.event_type,
                   e.tool_name, e.status, e.artifact_uri, e.details_json
            FROM agent_runs r LEFT JOIN execution_events e ON r.run_id=e.run_id
            WHERE r.trace_id=? ORDER BY e.timestamp
        """, (trace_id,)).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        self.connection.close()


class AgentMemoryService:
    """Coordinates all four agent-memory stores without mixing their roles."""

    def __init__(self, working: RedisWorkingMemory, semantic: CogneeBackend, executions: ExecutionStore, artifacts: FileArtifactStore):
        self.working, self.semantic, self.executions, self.artifacts = working, semantic, executions, artifacts

    async def start(self, trace_id: str, agent_name: str, task: str) -> str:
        run_id = self.executions.start_run(trace_id, agent_name, {"task": task})
        await self.working.put_json("agent-run", run_id, {"trace_id": trace_id, "task": task, "status": "running"})
        self.executions.record_event(run_id, "run_started", "ok", details={"task": task})
        await self.semantic.remember(f"Agent task: {task}\nTrace: {trace_id}", dataset=agent_name)
        return run_id

    async def record_tool_result(self, run_id: str, agent_name: str, tool_name: str, payload: Any, *, status: str) -> dict:
        artifact = self.artifacts.put_json(payload)
        self.executions.record_event(run_id, "tool_call", status, tool_name=tool_name, artifact_uri=artifact["uri"], details={"sha256": artifact["sha256"]})
        await self.working.append_event("agent-run", run_id, {"tool": tool_name, "status": status, "artifact": artifact})
        await self.semantic.remember(f"Tool {tool_name} returned {status}. Artifact SHA-256: {artifact['sha256']}", dataset=agent_name)
        return artifact

    async def recall(self, agent_name: str, query: str) -> Any:
        return await self.semantic.recall(query, dataset=agent_name)

    def finish(self, run_id: str, status: str) -> None:
        self.executions.record_event(run_id, "run_finished", status)
        self.executions.finish_run(run_id, status)
