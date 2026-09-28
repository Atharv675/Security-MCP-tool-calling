"""End-to-end tests: plain-English query -> Gemini selects a tool -> agent
executes it via MCP -> response is well-formed.

Requires a live GEMINI_API_KEY (these tests call the real Gemini API) and
spins up the FastMCP server as a subprocess for the session. Tests are
skipped automatically if GEMINI_API_KEY is not set.
"""

import os
import secrets

import pytest
import pytest_asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from client.agent import mcp_tools_to_gemini, resume_query, run_query
from client.llm_router import build_client
from tests._server_helpers import start_server, wait_until_ready

MCP_URL = "http://127.0.0.1:8091/mcp/"
TEST_AUTH_TOKEN = "test-token-for-e2e"

requires_api_key = pytest.mark.skipif(
    not os.environ.get("GEMINI_API_KEY"),
    reason="GEMINI_API_KEY not set; skipping live e2e tests",
)


@pytest.fixture(scope="session")
def mcp_server():
    proc = start_server("8091", TEST_AUTH_TOKEN)
    try:
        wait_until_ready(MCP_URL)
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest_asyncio.fixture
async def session(mcp_server):
    headers = {"Authorization": f"Bearer {TEST_AUTH_TOKEN}"}
    async with streamablehttp_client(MCP_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as sess:
            await sess.initialize()
            yield sess


@pytest_asyncio.fixture
async def agent_context(session):
    gemini_client = build_client(os.environ["GEMINI_API_KEY"])
    mcp_tools = (await session.list_tools()).tools
    tools = mcp_tools_to_gemini(mcp_tools)
    return session, gemini_client, tools


async def _resolve(session, client, tools, result, approve: bool = True) -> dict:
    """Auto-resolve any pending sensitive-tool approvals (approve or deny all)."""
    while result["status"] == "approval_needed":
        decisions = {c["id"]: approve for c in result["pending"]}
        result = await resume_query(session, client, tools, result["resume_state"], decisions)
    return result


def _last_tool_used(caplog) -> list[str]:
    return [
        line.split("Tool selected: ")[1].split(" |")[0]
        for line in caplog.messages
        if "Tool selected:" in line
    ]


@requires_api_key
@pytest.mark.asyncio
async def test_password_strength_tool(agent_context, caplog):
    session, client, tools = agent_context
    with caplog.at_level("INFO", logger="agent"):
        result = await run_query(session, client, tools, "Is the password 'hunter2' strong?")
        result = await _resolve(session, client, tools, result)
    assert "password_strength" in _last_tool_used(caplog)
    assert result["text"].strip() != ""


@requires_api_key
@pytest.mark.asyncio
async def test_hash_tool(agent_context, caplog):
    session, client, tools = agent_context
    with caplog.at_level("INFO", logger="agent"):
        result = await run_query(
            session, client, tools, "Give me the SHA256 hash of the text 'hello world'"
        )
        result = await _resolve(session, client, tools, result)
    assert "hash_password" in _last_tool_used(caplog)
    assert result["text"].strip() != ""


@requires_api_key
@pytest.mark.asyncio
async def test_cve_lookup_tool(agent_context, caplog):
    session, client, tools = agent_context
    with caplog.at_level("INFO", logger="agent"):
        result = await run_query(session, client, tools, "What is CVE-2021-44228 about?")
        result = await _resolve(session, client, tools, result)
    assert "cve_lookup" in _last_tool_used(caplog)
    assert "log4j" in result["text"].lower() or "log4shell" in result["text"].lower()


@requires_api_key
@pytest.mark.asyncio
async def test_log_analyzer_tool(agent_context, caplog):
    session, client, tools = agent_context
    log_snippet = (
        "Failed password for invalid user admin from 10.0.0.5\n"
        "Failed password for invalid user root from 10.0.0.5\n"
    )
    query = f"Analyze this log for security issues:\n{log_snippet}"
    with caplog.at_level("INFO", logger="agent"):
        result = await run_query(session, client, tools, query)
        result = await _resolve(session, client, tools, result)
    assert "log_analyzer" in _last_tool_used(caplog)
    assert result["text"].strip() != ""


@requires_api_key
@pytest.mark.asyncio
async def test_breach_check_requires_approval_and_distinguishes_results(agent_context, caplog):
    session, client, tools = agent_context

    with caplog.at_level("INFO", logger="agent"):
        breached_result = await run_query(
            session, client, tools, "Has the password 'password123' been breached before?"
        )
    assert breached_result["status"] == "approval_needed"
    assert any(c["tool"] == "breach_check" for c in breached_result["pending"])
    breached_result = await _resolve(session, client, tools, breached_result, approve=True)
    assert "breach_check" in _last_tool_used(caplog)
    assert "yes" in breached_result["text"].lower() or "breach" in breached_result["text"].lower()

    caplog.clear()
    random_password = secrets.token_urlsafe(24)
    with caplog.at_level("INFO", logger="agent"):
        strong_result = await run_query(
            session, client, tools, f"Has the password '{random_password}' been breached before?"
        )
        strong_result = await _resolve(session, client, tools, strong_result, approve=True)
    assert "breach_check" in _last_tool_used(caplog)
    assert "no" in strong_result["text"].lower() or "not" in strong_result["text"].lower()


@requires_api_key
@pytest.mark.asyncio
async def test_denying_breach_check_skips_the_call(agent_context, caplog):
    session, client, tools = agent_context
    with caplog.at_level("INFO", logger="agent"):
        result = await run_query(
            session, client, tools, "Has the password 'password123' been breached before?"
        )
        assert result["status"] == "approval_needed"
        result = await _resolve(session, client, tools, result, approve=False)
    # The tool itself must never have executed -- only the denial log line.
    assert "Tool selected: breach_check" not in "\n".join(caplog.messages)
    assert "Tool denied: breach_check" in "\n".join(caplog.messages)


@requires_api_key
@pytest.mark.asyncio
async def test_chained_password_strength_then_breach_check(agent_context, caplog):
    session, client, tools = agent_context
    with caplog.at_level("INFO", logger="agent"):
        result = await run_query(
            session,
            client,
            tools,
            "Is the password 'password123' secure, and has it been breached?",
        )
        result = await _resolve(session, client, tools, result, approve=True)
    tools_used = _last_tool_used(caplog)
    assert "password_strength" in tools_used
    assert "breach_check" in tools_used
    assert result["text"].strip() != ""


@requires_api_key
@pytest.mark.asyncio
async def test_malformed_log_analyzer_input_returns_structured_error(agent_context, caplog):
    session, client, tools = agent_context
    with caplog.at_level("INFO", logger="agent"):
        result = await run_query(
            session,
            client,
            tools,
            "Call the log_analyzer tool with no file_path and no raw_text arguments at all.",
        )
        result = await _resolve(session, client, tools, result)
    assert "log_analyzer" in _last_tool_used(caplog)
    # The tool itself must have returned a structured error, not crashed the server.
    assert any(
        "error" in line.lower()
        for line in caplog.messages
        if "Raw result (log_analyzer)" in line
    )
    assert result["text"].strip() != ""
