import json
import datetime as dt
from types import SimpleNamespace

import pytest

from client import agent
from client.a2a_pool import A2APool
from client.audit import reset_trace_id, set_trace_id
from client.audit_query import main as audit_query_main


class FakeSession:
    async def call_tool(self, name, args):
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps({"tool": name, "ok": True}))], isError=False)


class FailingSession:
    async def call_tool(self, name, args):
        raise TimeoutError("specialist timed out after 30 seconds")


def _call_interaction(name, args, call_id="call-1"):
    return SimpleNamespace(
        id="interaction-1",
        output_text="",
        steps=[SimpleNamespace(type="function_call", name=name, arguments=args, id=call_id)],
    )


def _answer_interaction(text="completed"):
    return SimpleNamespace(
        id="interaction-2", output_text=text,
        steps=[SimpleNamespace(type="message", text=text)],
    )


@pytest.mark.asyncio
async def test_trace_reconstructs_request_approval_denial_and_failure(monkeypatch, tmp_path):
    """A trace alone contains the route, the approval trail, and the error."""
    audit_path = tmp_path / "pipeline-audit.jsonl"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_path))

    responses = iter([
        _call_interaction("breach_check", {"password": "example"}),
        _answer_interaction("Denied call explained to user"),
        _call_interaction("password_strength", {"password": "example"}, "call-2"),
        _answer_interaction("Tool failure explained to user"),
    ])

    async def fake_send(*_args, **_kwargs):
        return next(responses)

    monkeypatch.setattr(agent, "send_interaction", fake_send)

    pending = await agent.run_query(FakeSession(), object(), [], "check breach status")
    assert pending["status"] == "approval_needed"
    trace_id = pending["trace_id"]
    completed = await agent.resume_query(
        FakeSession(), object(), [], pending["resume_state"], {"call-1": False}
    )
    assert completed["trace_id"] == trace_id

    failed = await agent.run_query(FailingSession(), object(), [], "score this password")
    assert failed["status"] == "answer"
    failure_trace_id = failed["trace_id"]

    records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    timeline = [r for r in records if r["trace_id"] == trace_id]
    assert [r["event"] for r in timeline if r["event"] in {"request_received", "routing_decision", "approval_requested", "approval_decision", "tool_call_denied", "final_answer"}] == [
        "request_received", "routing_decision", "approval_requested", "approval_decision", "tool_call_denied", "routing_decision", "final_answer"
    ]
    decision = next(r for r in timeline if r["event"] == "approval_decision")
    assert decision["approval_given"] is False and decision["actor"] == "user"

    failure = next(r for r in records if r["trace_id"] == failure_trace_id and r["event"] == "tool_call_finished")
    assert failure["error"] and "timed out" in failure["error"]


def test_audit_query_cli_filters_timeline_tools_and_denials(monkeypatch, tmp_path, capsys):
    audit_path = tmp_path / "audit.jsonl"
    today = dt.datetime.now(dt.timezone.utc).isoformat()
    audit_path.write_text("\n".join([
        json.dumps({"timestamp": today, "trace_id": "t1", "event": "tool_call_finished", "tool": "x"}),
        json.dumps({"timestamp": today, "trace_id": "t1", "event": "approval_decision", "approval_given": False}),
    ]) + "\n", encoding="utf-8")

    # Timeline and tool queries are trace-based and work on any historical log.
    monkeypatch.setattr("sys.argv", ["audit_query", "tools", "t1", "--log", str(audit_path)])
    audit_query_main()
    assert '"tool": "x"' in capsys.readouterr().out

    monkeypatch.setattr("sys.argv", ["audit_query", "denied-today", "--log", str(audit_path)])
    audit_query_main()
    assert '"denied_approvals": 1' in capsys.readouterr().out


@pytest.mark.asyncio
async def test_specialist_connection_failure_is_traceable(monkeypatch, tmp_path):
    audit_path = tmp_path / "a2a-audit.jsonl"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_path))
    pool = A2APool([])
    pool._routes["credential-breach-check"] = "http://127.0.0.1:19999"
    token = set_trace_id("specialist-failure-trace")
    try:
        result = await pool.call_tool("credential-breach-check", {"password": "x"})
    finally:
        reset_trace_id(token)
        await pool.aclose()

    assert result.isError is True
    record = next(
        json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["event"] == "specialist_call_failed"
    )
    assert record["trace_id"] == "specialist-failure-trace"
    assert record["specialist_url"] == "http://127.0.0.1:19999"
    assert "Connect" in record["error"] or "Error" in record["error"]
