"""In-memory scan history log, exposed as an MCP resource.

Every tool invocation records a short entry here (most recent first), so an
agent can pull recent findings via the `scan://history` resource -- e.g. to
feed into the `generate_security_report` prompt.
"""

from collections import deque
from datetime import datetime, timezone

_MAX_HISTORY = 200
_HISTORY: deque[dict] = deque(maxlen=_MAX_HISTORY)


def record_scan(tool: str, args: dict, status: str, summary: str) -> None:
    """Record one tool invocation. `status` is "ok" or "error"."""
    _HISTORY.appendleft({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "args": args,
        "status": status,
        "summary": summary[:300],
    })


def get_history(limit: int = 50) -> list[dict]:
    return list(_HISTORY)[:limit]


if __name__ == "__main__":
    record_scan("password_strength", {"password": "***"}, "ok", "verdict=weak")
    record_scan("breach_check", {"password": "***"}, "ok", "breached=True times_seen=123")
    print(get_history())
