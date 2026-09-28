"""Shared MCP <-> Gemini conversion helpers.

Split out from client/agent.py so both the single-connection path (agent.py)
and the multi-server pool (client/mcp_pool.py) can use them without a
circular import.
"""

import os

_UNSUPPORTED_SCHEMA_KEYS = {"$schema", "$id", "additionalProperties", "title"}


def auth_headers(token: str | None = None) -> dict[str, str]:
    """Bearer-auth header for the MCP transport. Reads MCP_AUTH_TOKEN if no
    token is given explicitly (the multi-server pool passes per-server tokens)."""
    token = token if token is not None else os.environ.get("MCP_AUTH_TOKEN")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def sanitize_schema(schema):
    """Strip JSON Schema keywords Gemini's function-parameter schema doesn't use."""
    if isinstance(schema, dict):
        return {
            key: sanitize_schema(value)
            for key, value in schema.items()
            if key not in _UNSUPPORTED_SCHEMA_KEYS
        }
    if isinstance(schema, list):
        return [sanitize_schema(item) for item in schema]
    return schema


def mcp_tool_to_gemini(tool, name_override: str | None = None) -> dict:
    """Convert one MCP tool schema to Gemini's function-tool shape.

    `name_override` lets the multi-server pool expose a namespaced name
    (e.g. "srv2__breach_check") to Gemini while keeping the real MCP call
    routed under the tool's original, unqualified name.
    """
    return {
        "type": "function",
        "name": name_override or tool.name,
        "description": tool.description or "",
        "parameters": sanitize_schema(tool.inputSchema),
    }


def mcp_tools_to_gemini(mcp_tools) -> list[dict]:
    """Convert MCP tool schemas to Gemini's function-tool shape.

    No hardcoded tool list -- this runs over whatever list_tools() returns.
    """
    return [mcp_tool_to_gemini(tool) for tool in mcp_tools]
