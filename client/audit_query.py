"""Small CLI for inspecting append-only JSONL audit records.

Examples: python -m client.audit_query timeline TRACE_ID
          python -m client.audit_query tools TRACE_ID
          python -m client.audit_query denied-today
"""

import argparse
import datetime as dt
import json
from pathlib import Path

from client.audit import audit_log_path


def _records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="Query pipeline audit JSONL records")
    parser.add_argument("command", choices=["timeline", "tools", "denied-today"])
    parser.add_argument("trace_id", nargs="?")
    parser.add_argument("--log", type=Path, default=audit_log_path())
    args = parser.parse_args()
    records = _records(args.log)

    if args.command in {"timeline", "tools"}:
        if not args.trace_id:
            parser.error("trace_id is required for timeline and tools")
        records = [r for r in records if r.get("trace_id") == args.trace_id]
        if args.command == "tools":
            records = [r for r in records if r.get("tool")]
    else:
        today = dt.datetime.now(dt.timezone.utc).date().isoformat()
        records = [
            r for r in records
            if r.get("event") == "approval_decision"
            and r.get("approval_given") is False
            and str(r.get("timestamp", "")).startswith(today)
        ]
        print(json.dumps({"date": today, "denied_approvals": len(records)}))
        return
    for record in sorted(records, key=lambda r: r.get("timestamp", "")):
        print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
