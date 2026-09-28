"""Append-only structured audit logging and a request-scoped trace context."""

import contextvars
import datetime as dt
import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any

_trace_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("trace_id", default=None)
_write_lock = threading.Lock()


def new_trace_id() -> str:
    return str(uuid.uuid4())


def current_trace_id() -> str | None:
    return _trace_id.get()


def set_trace_id(trace_id: str):
    return _trace_id.set(trace_id)


def reset_trace_id(token) -> None:
    _trace_id.reset(token)


def audit_log_path() -> Path:
    return Path(os.environ.get("AUDIT_LOG_PATH", "audit.jsonl"))


def _json_safe(value: Any) -> Any:
    """Keep logging reliable even when SDK objects/exceptions are supplied."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def log_event(
    event: str,
    *,
    trace_id: str | None = None,
    actor: str | None = None,
    agent: str | None = None,
    tool: str | None = None,
    input: Any = None,
    result: Any = None,
    error: Any = None,
    approval_required: bool = False,
    approval_given: bool | None = None,
    **extra: Any,
) -> dict:
    """Write one JSON Lines record. Each record is independently queryable."""
    record = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "event": event,
        "trace_id": trace_id or current_trace_id(),
        "actor": actor,
        "agent": agent,
        "tool": tool,
        "input": _json_safe(input),
        "result": _json_safe(result),
        "error": _json_safe(error),
        "approval_required": approval_required,
        "approval_given": approval_given,
        **{key: _json_safe(value) for key, value in extra.items()},
    }
    path = audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # One write per record, protected within a process. Appending keeps the
    # shared pipeline log durable across the orchestrator and specialists.
    line = json.dumps(record, sort_keys=True, default=str) + "\n"
    with _write_lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
    return record
