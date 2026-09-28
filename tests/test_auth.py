"""Transport auth tests: missing/invalid/valid bearer token against the MCP server.

Pure MCP/HTTP checks -- no GEMINI_API_KEY needed, so these always run.
"""

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from tests._server_helpers import start_server, wait_until_ready

MCP_URL = "http://127.0.0.1:8092/mcp/"
VALID_TOKEN = "test-token-for-auth"


@pytest.fixture(scope="module")
def mcp_server():
    proc = start_server("8092", VALID_TOKEN)
    try:
        wait_until_ready(MCP_URL)
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.mark.asyncio
async def test_missing_token_rejected(mcp_server):
    with pytest.raises((httpx.HTTPStatusError, ExceptionGroup)) as exc_info:
        async with streamablehttp_client(MCP_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
    assert _status_code(exc_info.value) == 401


@pytest.mark.asyncio
async def test_invalid_token_rejected(mcp_server):
    headers = {"Authorization": "Bearer wrong-token"}
    with pytest.raises((httpx.HTTPStatusError, ExceptionGroup)) as exc_info:
        async with streamablehttp_client(MCP_URL, headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
    assert _status_code(exc_info.value) == 401


@pytest.mark.asyncio
async def test_valid_token_accepted(mcp_server):
    headers = {"Authorization": f"Bearer {VALID_TOKEN}"}
    async with streamablehttp_client(MCP_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert len(tools.tools) == 6


def _status_code(exc) -> int | None:
    """Dig an HTTP status code out of an (possibly nested) exception/ExceptionGroup."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code
    if hasattr(exc, "exceptions"):
        for inner in exc.exceptions:
            code = _status_code(inner)
            if code is not None:
                return code
    return None
