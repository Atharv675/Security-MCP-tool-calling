"""A2A server: security specialist.

Wraps the existing MCP-backed toolkit (server/main.py) as A2A skills --
publishes an Agent Card so another agent can tell what it's good for
(password strength/hashing, credential breach checks, CVE lookup, log
analysis) without knowing it's MCP underneath. Each skill call maps 1:1 to
an MCP tool call. No skill-selection logic here -- the specialist trusts
whatever skill+input the caller (the orchestrator) hands it; see
agents/orchestrator.py for where the approval gate for sensitive skills
lives instead.

Run with: python -m agents.security_specialist
(the MCP server, server/main.py, must already be running)
"""

import contextlib
import json
import os

from dotenv import load_dotenv

# pyrefly: ignore [missing-import]
import uvicorn
from a2a.compat.v0_3 import types as a2a_types
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from agents.a2a_common import build_app
from agents.skills import SECURITY_SKILLS
from client.audit import log_event
from client.mcp_utils import auth_headers

load_dotenv()

HOST = os.environ.get("SECURITY_SPECIALIST_HOST", "127.0.0.1")
PORT = int(os.environ.get("SECURITY_SPECIALIST_PORT", "8100"))
PUBLIC_URL = os.environ.get("SECURITY_SPECIALIST_URL", f"http://{HOST}:{PORT}")
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp/")

_session: ClientSession | None = None
_stack: contextlib.AsyncExitStack | None = None


def _build_agent_card() -> a2a_types.AgentCard:
    skills = [
        a2a_types.AgentSkill(
            id=skill_id,
            name=skill_id.replace("-", " ").title(),
            description=info["description"],
            tags=["security"],
        )
        for skill_id, info in SECURITY_SKILLS.items()
    ]
    return a2a_types.AgentCard(
        name="Security Specialist",
        description=(
            "MCP-backed security toolkit: password strength scoring and hashing, "
            "credential breach checks, CVE lookup, and log analysis."
        ),
        url=PUBLIC_URL.rstrip("/") + "/",
        version="1.0.0",
        capabilities=a2a_types.AgentCapabilities(streaming=False),
        defaultInputModes=["text/plain"],
        defaultOutputModes=["text/plain"],
        skills=skills,
    )


async def _handle_skill(skill_id: str, skill_input: dict) -> dict:
    info = SECURITY_SKILLS.get(skill_id)
    if info is None:
        return {"error": f"unknown skill: {skill_id}"}
    if _session is None:
        return {"error": "security specialist not connected to the MCP server yet"}

    log_event("mcp_tool_call_started", agent="Security Specialist", tool=info["tool"], input=skill_input)
    try:
        result = await _session.call_tool(info["tool"], skill_input)
        text = "\n".join(block.text for block in result.content if hasattr(block, "text"))
        is_error = bool(getattr(result, "isError", False))
    except Exception as exc:  # noqa: BLE001
        log_event("mcp_tool_call_failed", agent="Security Specialist", tool=info["tool"], input=skill_input, error=str(exc))
        return {"error": f"MCP tool call failed: {exc}"}
    log_event(
        "mcp_tool_call_finished" if not is_error else "mcp_tool_call_failed",
        agent="Security Specialist", tool=info["tool"], input=skill_input, result=text,
        error=text if is_error else None,
    )
    if is_error:
        return {"error": text}
    try:
        return json.loads(text)
    except ValueError:
        return {"result": text}


async def _startup() -> None:
    global _session, _stack
    _stack = contextlib.AsyncExitStack()
    try:
        read, write, _ = await _stack.enter_async_context(
            streamablehttp_client(MCP_SERVER_URL, headers=auth_headers())
        )
        _session = await _stack.enter_async_context(ClientSession(read, write))
        await _session.initialize()
    except Exception as exc:
        if _stack is not None:
            await _stack.aclose()
            _stack = None
        raise RuntimeError(
            f"Failed to connect to MCP server at {MCP_SERVER_URL}: {exc}. "
            "Please ensure 'python -m server.main' is running first!"
        ) from exc


async def _shutdown() -> None:
    global _stack, _session
    if _stack is not None:
        await _stack.aclose()
        _stack = None
        _session = None


app = build_app(_build_agent_card(), _handle_skill, on_startup=_startup, on_shutdown=_shutdown)

if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
