"""Import existing chat history from audit.jsonl into the Obsidian vault.

The audit log (audit.jsonl) records every agent interaction as JSON Lines.
This script reads it, groups records by trace_id (= one conversation), and
writes each conversation as a Markdown note into the Obsidian vault under:

    MCP Memory/Chats/YYYY-MM-DD-<trace_id>.md

Run once:
    python import_history_to_obsidian.py
    python import_history_to_obsidian.py --audit path/to/audit.jsonl
    python import_history_to_obsidian.py --dry-run   (preview, no writes)
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _load_records(audit_path: Path) -> list[dict]:
    if not audit_path.exists():
        print(f"[WARN] Audit log not found: {audit_path}")
        return []
    records = []
    for i, line in enumerate(audit_path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(f"[WARN] Skipping malformed JSON at line {i}: {exc}")
    return records


def _group_by_trace(records: list[dict]) -> dict[str, list[dict]]:
    """Group records by trace_id, preserving chronological order."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        tid = r.get("trace_id")
        if tid:
            groups[tid].append(r)
    # Sort each group by timestamp
    for tid in groups:
        groups[tid].sort(key=lambda r: r.get("timestamp", ""))
    return dict(groups)


def _conversation_date(records: list[dict]) -> str:
    """Return ISO date string from the first record's timestamp."""
    for r in records:
        ts = r.get("timestamp", "")
        if ts:
            return ts[:10]  # YYYY-MM-DD
    return "unknown-date"


def _build_markdown(trace_id: str, records: list[dict]) -> str:
    """Convert a list of audit records for one trace into a Markdown note."""
    date = _conversation_date(records)

    # Extract user query and final answer
    user_query = None
    final_answer = None
    tool_calls: list[dict] = []

    for r in records:
        event = r.get("event", "")
        if event == "request_received" and user_query is None:
            inp = r.get("input", "")
            if isinstance(inp, str) and inp:
                user_query = inp
            elif isinstance(inp, dict):
                user_query = json.dumps(inp, indent=2)
        elif event == "final_answer" and final_answer is None:
            res = r.get("result", "")
            if res:
                final_answer = str(res)
        elif event in ("tool_call_finished", "tool_call_started") and r.get("tool"):
            tool_calls.append(r)

    # Build frontmatter
    lines = [
        "---",
        f"conversation_id: {json.dumps(trace_id)}",
        f"date: {date}",
        f"imported_from: audit.jsonl",
        f"memory_type: long_term_chat",
        "---",
        "",
        f"# Conversation — {date}",
        "",
    ]

    # User turn
    if user_query:
        first_ts = _conversation_date(records)
        lines += [
            f"## {first_ts} — user",
            "",
            user_query,
            "",
        ]

    # Tool calls (summarised)
    finished_tools = [t for t in tool_calls if t.get("event") == "tool_call_finished"]
    if finished_tools:
        lines += ["## 🔧 Tool Calls", ""]
        seen = set()
        for t in finished_tools:
            tool_name = t.get("tool", "unknown")
            if tool_name in seen:
                continue
            seen.add(tool_name)
            status = "✅" if not t.get("error") else "❌"
            ts = t.get("timestamp", "")[:19]
            lines.append(f"- {status} `{tool_name}` — {ts}")
        lines.append("")

    # Assistant answer
    if final_answer:
        last_ts = records[-1].get("timestamp", date)[:19]
        lines += [
            f"## {last_ts} — assistant",
            "",
            final_answer,
            "",
        ]

    # Raw event count
    lines += [
        "---",
        f"*{len(records)} audit events imported from audit.jsonl*",
    ]

    return "\n".join(lines)


def import_to_obsidian(
    audit_path: Path,
    vault_root: Path,
    *,
    dry_run: bool = False,
    overwrite: bool = False,
) -> int:
    """Import audit.jsonl into the Obsidian vault. Returns number of notes written."""
    records = _load_records(audit_path)
    if not records:
        print("No records found — nothing to import.")
        return 0

    groups = _group_by_trace(records)
    print(f"Found {len(records)} records across {len(groups)} conversation(s) in {audit_path}")

    chats_dir = vault_root / "Chats"
    if not dry_run:
        chats_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    skipped = 0
    for trace_id, trace_records in groups.items():
        date = _conversation_date(trace_records)
        safe_id = trace_id.replace("-", "")[:16]
        note_name = f"{date}-{safe_id}.md"
        note_path = chats_dir / note_name

        if note_path.exists() and not overwrite:
            skipped += 1
            print(f"  [SKIP] {note_name}  (already exists, use --overwrite to replace)")
            continue

        content = _build_markdown(trace_id, trace_records)

        if dry_run:
            print(f"  [DRY-RUN] Would write: {note_path}")
            print(f"            {len(trace_records)} events, {len(content)} chars")
        else:
            note_path.write_text(content, encoding="utf-8")
            print(f"  [OK] {note_path}")
            written += 1

    print(f"\nDone. {written} note(s) written, {skipped} skipped.")
    return written


def main() -> None:
    from client.audit import audit_log_path
    from memory.settings import build_chat_memory

    parser = argparse.ArgumentParser(
        description="Import existing audit.jsonl chat history into the Obsidian vault."
    )
    parser.add_argument(
        "--audit",
        type=Path,
        default=audit_log_path(),
        help="Path to audit.jsonl (default: reads AUDIT_LOG_PATH from .env)",
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=None,
        help="Path to Obsidian vault (default: reads OBSIDIAN_VAULT_PATH from .env)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be written without actually writing.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing notes (default: skip already-imported conversations).",
    )
    args = parser.parse_args()

    vault_root: Path
    if args.vault:
        vault_root = args.vault
    else:
        chat_svc = build_chat_memory()
        vault_root = chat_svc.vault.root

    print(f"Obsidian vault : {vault_root}")
    print(f"Audit log      : {args.audit}")
    if args.dry_run:
        print("Mode           : DRY RUN (no files will be written)")
    print()

    count = import_to_obsidian(
        args.audit, vault_root, dry_run=args.dry_run, overwrite=args.overwrite
    )
    sys.exit(0 if count >= 0 else 1)


if __name__ == "__main__":
    main()
