"""Tests for the multi-server MCP pool (client/mcp_pool.py).

Pure MCP/HTTP checks against two real server instances -- no Gemini API
calls, so these always run regardless of GEMINI_API_KEY / quota.
"""

import pytest

from client.mcp_pool import MultiServerPool, ServerConfig, load_server_configs
from tests._server_helpers import start_server, wait_until_ready

TOKEN_1 = "test-token-srv1"
TOKEN_2 = "test-token-srv2"
URL_1 = "http://127.0.0.1:8093/mcp/"
URL_2 = "http://127.0.0.1:8094/mcp/"


@pytest.fixture(scope="module")
def two_servers():
    procs = [start_server("8093", TOKEN_1), start_server("8094", TOKEN_2)]
    try:
        wait_until_ready(URL_1)
        wait_until_ready(URL_2)
        yield
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            proc.wait(timeout=10)


def test_load_server_configs_multi(monkeypatch):
    monkeypatch.setenv("MCP_SERVER_URLS", f"{URL_1},{URL_2}")
    monkeypatch.setenv("MCP_AUTH_TOKENS", f"{TOKEN_1},{TOKEN_2}")
    configs = load_server_configs()
    assert [c.url for c in configs] == [URL_1, URL_2]
    assert [c.token for c in configs] == [TOKEN_1, TOKEN_2]
    assert [c.server_id for c in configs] == ["srv1", "srv2"]


def test_load_server_configs_single_server_unaffected(monkeypatch):
    monkeypatch.delenv("MCP_SERVER_URLS", raising=False)
    monkeypatch.setenv("MCP_SERVER_URL", URL_1)
    configs = load_server_configs()
    assert len(configs) == 1
    assert configs[0].url == URL_1


@pytest.mark.asyncio
async def test_pool_merges_and_namespaces_tools_across_servers(two_servers):
    pool = MultiServerPool([
        ServerConfig("srv1", URL_1, TOKEN_1),
        ServerConfig("srv2", URL_2, TOKEN_2),
    ])
    await pool.connect()
    try:
        assert pool.multi is True
        # Every tool exposed to Gemini is namespaced when >1 server is configured.
        assert all("__" in name for name in pool.tool_names)
        assert "srv1__password_strength" in pool.tool_names
        assert "srv2__password_strength" in pool.tool_names
        # 6 tools per server, 2 servers.
        assert len(pool.tool_names) == 12
        # original_name() strips the namespace back off for policy checks.
        assert pool.original_name("srv1__breach_check") == "breach_check"
        assert pool.original_name("srv2__breach_check") == "breach_check"
    finally:
        await pool.aclose()


@pytest.mark.asyncio
async def test_pool_routes_call_tool_to_the_right_server(two_servers):
    pool = MultiServerPool([
        ServerConfig("srv1", URL_1, TOKEN_1),
        ServerConfig("srv2", URL_2, TOKEN_2),
    ])
    await pool.connect()
    try:
        result_1 = await pool.call_tool("srv1__password_strength", {"password": "hunter2"})
        result_2 = await pool.call_tool("srv2__password_strength", {"password": "hunter2"})
        assert not result_1.isError
        assert not result_2.isError
        assert "verdict" in result_1.content[0].text
        assert "verdict" in result_2.content[0].text
    finally:
        await pool.aclose()


@pytest.mark.asyncio
async def test_pool_single_server_mode_does_not_namespace(two_servers):
    """With exactly one server configured, tool names are unqualified --
    identical to pre-multi-server behavior."""
    pool = MultiServerPool([ServerConfig("srv1", URL_1, TOKEN_1)])
    await pool.connect()
    try:
        assert pool.multi is False
        assert "password_strength" in pool.tool_names
        assert not any("__" in name for name in pool.tool_names)
        assert pool.original_name("password_strength") == "password_strength"
    finally:
        await pool.aclose()


@pytest.mark.asyncio
async def test_pool_read_resource_and_get_prompt(two_servers):
    pool = MultiServerPool([
        ServerConfig("srv1", URL_1, TOKEN_1),
        ServerConfig("srv2", URL_2, TOKEN_2),
    ])
    await pool.connect()
    try:
        history = await pool.read_resource("scan://history")
        assert history.contents

        prompt = await pool.get_prompt(
            "generate_security_report", {"target": "example.com", "findings": "[]"}
        )
        assert "example.com" in prompt.messages[0].content.text
    finally:
        await pool.aclose()
