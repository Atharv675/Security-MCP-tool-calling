"""Tests for the A2A pipeline: security specialist + report-writer specialist
+ triage orchestrator.

- The failure-case test is quota-free (no Gemini calls) and always runs.
- The single-specialist and chained-specialist tests call the real Gemini
  API through the orchestrator's tool-use loop, so they're skipped unless
  GEMINI_API_KEY is set, matching tests/test_e2e.py's pattern.
"""

import os
import subprocess
import sys
import time

import pytest
import pytest_asyncio

from client.a2a_pool import A2APool, SpecialistConfig, load_specialist_configs
from client.agent import resume_query, run_query
from client.llm_router import build_client
from tests._server_helpers import start_server, wait_until_ready

MCP_URL = "http://127.0.0.1:8095/mcp/"
SECURITY_URL = "http://127.0.0.1:8195"
REPORT_URL = "http://127.0.0.1:8295"
MCP_TOKEN = "test-token-a2a-mcp"

requires_api_key = pytest.mark.skipif(
    not os.environ.get("GEMINI_API_KEY"),
    reason="GEMINI_API_KEY not set; skipping live e2e tests",
)


def _start_specialist(module: str, port_env: str, port: str, extra_env: dict | None = None) -> subprocess.Popen:
    env = {**os.environ, port_env: port}
    env.update(extra_env or {})
    return subprocess.Popen(
        [sys.executable, "-m", module], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


@pytest.fixture(scope="module")
def pipeline():
    """MCP server + both A2A specialists, all real subprocesses."""
    mcp_proc = start_server("8095", MCP_TOKEN)
    procs = [mcp_proc]
    try:
        wait_until_ready(MCP_URL)

        security_proc = _start_specialist(
            "agents.security_specialist",
            "SECURITY_SPECIALIST_PORT",
            "8195",
            {"MCP_SERVER_URL": MCP_URL, "MCP_AUTH_TOKEN": MCP_TOKEN},
        )
        procs.append(security_proc)
        wait_until_ready(f"{SECURITY_URL}/.well-known/agent-card.json")

        report_proc = _start_specialist("agents.report_writer_specialist", "REPORT_WRITER_PORT", "8295")
        procs.append(report_proc)
        wait_until_ready(f"{REPORT_URL}/.well-known/agent-card.json")

        yield
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            proc.wait(timeout=10)


def test_load_specialist_configs_defaults(monkeypatch):
    monkeypatch.delenv("A2A_SPECIALIST_URLS", raising=False)
    monkeypatch.setenv("SECURITY_SPECIALIST_URL", SECURITY_URL)
    monkeypatch.setenv("REPORT_WRITER_URL", REPORT_URL)
    configs = load_specialist_configs()
    assert [c.url for c in configs] == [SECURITY_URL, REPORT_URL]


@pytest.mark.asyncio
async def test_a2a_pool_reports_specialist_failure_cleanly():
    """Failure case: an unreachable specialist should fail fast with a
    structured tool-error result, not hang or raise out of call_tool."""
    pool = A2APool([])
    # Skip discovery entirely and point a known skill at a port nothing is
    # listening on -- this is exactly the "specialist times out or errors"
    # scenario the orchestrator's approval-gated loop must absorb cleanly.
    pool._routes["credential-breach-check"] = "http://127.0.0.1:19999"

    start = time.monotonic()
    result = await pool.call_tool("credential-breach-check", {"password": "x"})
    elapsed = time.monotonic() - start

    assert result.isError is True
    assert "failed" in result.content[0].text.lower()
    assert elapsed < 30  # connection-refused, should fail almost instantly

    await pool.aclose()


@pytest.mark.asyncio
async def test_a2a_pool_unknown_skill_reports_cleanly():
    pool = A2APool([])
    result = await pool.call_tool("does-not-exist", {})
    assert result.isError is True
    assert "unknown skill" in result.content[0].text.lower()
    await pool.aclose()


@requires_api_key
@pytest.mark.asyncio
async def test_single_specialist_query(pipeline, caplog):
    gemini_client = build_client(os.environ["GEMINI_API_KEY"])
    pool = A2APool([SpecialistConfig(url=SECURITY_URL), SpecialistConfig(url=REPORT_URL)])
    await pool.connect()
    try:
        with caplog.at_level("INFO", logger="agent"):
            result = await run_query(
                pool, gemini_client, pool.tools,
                "Analyze this log for security issues:\nFailed password for invalid user admin from 10.0.0.5",
            )
            while result["status"] == "approval_needed":
                decisions = {c["id"]: True for c in result["pending"]}
                result = await resume_query(pool, gemini_client, pool.tools, result["resume_state"], decisions)
        assert "log-analysis" in [
            line.split("Tool selected: ")[1].split(" |")[0] for line in caplog.messages if "Tool selected:" in line
        ]
        assert result["status"] == "answer"
        assert result["text"].strip() != ""
    finally:
        await pool.aclose()


@requires_api_key
@pytest.mark.asyncio
async def test_chained_security_then_report_writer(pipeline, caplog):
    gemini_client = build_client(os.environ["GEMINI_API_KEY"])
    pool = A2APool([SpecialistConfig(url=SECURITY_URL), SpecialistConfig(url=REPORT_URL)])
    await pool.connect()
    try:
        with caplog.at_level("INFO", logger="agent"):
            result = await run_query(
                pool, gemini_client, pool.tools,
                "Check if the password 'password123' has been breached, then write me a short report on it.",
            )
            while result["status"] == "approval_needed":
                decisions = {c["id"]: True for c in result["pending"]}
                result = await resume_query(pool, gemini_client, pool.tools, result["resume_state"], decisions)

        tools_used = [
            line.split("Tool selected: ")[1].split(" |")[0] for line in caplog.messages if "Tool selected:" in line
        ]
        assert "credential-breach-check" in tools_used
        assert "report-generation" in tools_used
        assert result["status"] == "answer"
        assert result["text"].strip() != ""
    finally:
        await pool.aclose()
