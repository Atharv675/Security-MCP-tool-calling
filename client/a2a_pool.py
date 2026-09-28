"""A2A specialist connection pool.

Duck-type compatible with client/mcp_pool.py::MultiServerPool for the
operations client/agent.py's tool-use loop needs (call_tool, original_name),
so the orchestrator (agents/orchestrator.py) can reuse that loop --
including the approval gate and the resumable state machine -- completely
unchanged, with A2A specialists standing in for MCP servers.

original_name() is the key piece that makes the approval gate "just work":
it maps an A2A skill id (e.g. "credential-breach-check") back to the
underlying MCP tool name ("breach_check") via agents/skills.py, so
client/agent.py's existing SENSITIVE_TOOLS = {"breach_check", "cve_lookup"}
check applies to A2A delegation without any changes there.
"""

import asyncio
import json
import os
import uuid
from dataclasses import dataclass, field

import httpx
from a2a.compat.v0_3 import types as a2a_types
from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH

from agents.skills import ALL_SKILLS
from client.audit import current_trace_id, log_event

# Generous default: the report-generation skill calls Gemini internally,
# which has been observed taking several minutes in practice (see
# client/runtime.py's own long timeout for the same reason).
_CALL_TIMEOUT_SECONDS = 300


class _TextBlock:
    def __init__(self, text: str):
        self.text = text


class _ToolResult:
    """Duck-type stand-in for mcp.types.CallToolResult: .content[i].text, .isError."""

    def __init__(self, text: str, is_error: bool = False):
        self.content = [_TextBlock(text)]
        self.isError = is_error


@dataclass
class SpecialistConfig:
    url: str


def load_specialist_configs() -> list[SpecialistConfig]:
    urls_env = os.environ.get("A2A_SPECIALIST_URLS", "").strip()
    if urls_env:
        urls = [u.strip() for u in urls_env.split(",") if u.strip()]
    else:
        urls = [
            os.environ.get("SECURITY_SPECIALIST_URL", "http://127.0.0.1:8100"),
            os.environ.get("REPORT_WRITER_URL", "http://127.0.0.1:8200"),
        ]
    return [SpecialistConfig(url=u.rstrip("/")) for u in urls]


@dataclass
class A2APool:
    configs: list[SpecialistConfig]
    tools: list[dict] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    agent_cards: list[dict] = field(default_factory=list)

    def __post_init__(self):
        # httpx's own default timeout (5s) is shorter than _CALL_TIMEOUT_SECONDS,
        # and would fire before the asyncio.wait_for below ever gets a chance to.
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(_CALL_TIMEOUT_SECONDS))
        self._routes: dict[str, str] = {}  # skill_id -> specialist base url

    async def connect(self) -> None:
        for cfg in self.configs:
            resp = await self._client.get(f"{cfg.url}{AGENT_CARD_WELL_KNOWN_PATH}")
            resp.raise_for_status()
            card = a2a_types.AgentCard.model_validate(resp.json())
            self.agent_cards.append(
                {"url": cfg.url, "name": card.name, "skills": [s.id for s in card.skills]}
            )
            for skill in card.skills:
                self._routes[skill.id] = cfg.url
                known = ALL_SKILLS.get(skill.id)
                parameters = known["parameters"] if known else {"type": "object", "properties": {}}
                self.tools.append(
                    {
                        "type": "function",
                        "name": skill.id,
                        "description": skill.description,
                        "parameters": parameters,
                    }
                )
                self.tool_names.append(skill.id)

    def original_name(self, skill_id: str) -> str:
        known = ALL_SKILLS.get(skill_id)
        return known["tool"] if known and "tool" in known else skill_id

    async def call_tool(self, skill_id: str, args: dict):
        base_url = self._routes.get(skill_id)
        if base_url is None:
            log_event("specialist_call_failed", agent="orchestrator", tool=skill_id, input=args, error="unknown skill")
            return _ToolResult(f"unknown skill: {skill_id}", is_error=True)

        trace_id = current_trace_id()
        log_event("specialist_delegation_started", agent="orchestrator", tool=skill_id, input=args, specialist_url=base_url)

        message = a2a_types.Message(
            messageId=str(uuid.uuid4()),
            role=a2a_types.Role.user,
            parts=[a2a_types.Part(a2a_types.TextPart(text=json.dumps(
                {"skill": skill_id, "input": args, "trace_id": trace_id}
            )))],
        )
        rpc_request = a2a_types.SendMessageRequest(
            id=str(uuid.uuid4()), params=a2a_types.MessageSendParams(message=message)
        )

        try:
            resp = await asyncio.wait_for(
                self._client.post(
                    base_url + "/",
                    json=rpc_request.model_dump(mode="json", by_alias=True, exclude_none=True),
                ),
                timeout=_CALL_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            body = resp.json()
        except Exception as exc:  # noqa: BLE001 - network/timeout error -> clean tool-error result
            detail = f"{type(exc).__name__}: {exc}"
            log_event(
                "specialist_call_failed", agent="orchestrator", tool=skill_id, input=args,
                error=detail, specialist_url=base_url, timeout_seconds=_CALL_TIMEOUT_SECONDS,
            )
            return _ToolResult(f"A2A call to '{skill_id}' at {base_url} failed: {detail}", is_error=True)

        if "error" in body:
            log_event("specialist_call_failed", agent="orchestrator", tool=skill_id, input=args, result=body, error=body["error"])
            return _ToolResult(f"A2A error from '{skill_id}': {body['error']}", is_error=True)

        try:
            result_message = a2a_types.Message.model_validate(body["result"])
            text = "\n".join(p.root.text for p in result_message.parts if p.root.kind == "text")
        except Exception as exc:  # noqa: BLE001 - malformed response -> clean tool-error result
            log_event("specialist_call_failed", agent="orchestrator", tool=skill_id, input=args, error=str(exc))
            return _ToolResult(f"malformed A2A response from '{skill_id}': {exc}", is_error=True)

        try:
            payload = json.loads(text)
            is_error = isinstance(payload, dict) and "error" in payload
        except (ValueError, TypeError):
            is_error = False
        log_event(
            "specialist_delegation_finished" if not is_error else "specialist_call_failed",
            agent="orchestrator", tool=skill_id, input=args, result=text,
            error=text if is_error else None, specialist_url=base_url,
        )
        return _ToolResult(text, is_error=is_error)

    async def aclose(self) -> None:
        await self._client.aclose()
