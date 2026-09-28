"""Shared A2A server plumbing: agent-card discovery route + a JSON-RPC
message/send endpoint, built directly on Starlette using a2a-sdk's v0.3
pydantic-compat types (a2a.compat.v0_3.types).

Deliberately hand-rolled rather than using a2a-sdk's higher-level server
classes (AgentExecutor/DefaultRequestHandler/EventQueue) -- those add an
async event-queue execution model built for long-running/streaming tasks,
which these single-turn skill calls don't need. The wire format (JSON-RPC
"message/send", the /.well-known/agent-card.json discovery path) is real
A2A v0.3, grounded via introspection of the installed package -- not
guessed.
"""

import json
import uuid
from contextlib import asynccontextmanager
from typing import Awaitable, Callable, Optional

from a2a.compat.v0_3 import types as a2a_types
from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from client.audit import log_event, reset_trace_id, set_trace_id

# (skill_id, input_dict) -> result dict. Must not raise -- return {"error": ...} instead.
SkillHandler = Callable[[str, dict], Awaitable[dict]]
LifecycleHook = Callable[[], Awaitable[None]]


def _rpc_error(request_id, code: int, message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        status_code=status_code,
    )


def build_app(
    agent_card: a2a_types.AgentCard,
    handler: SkillHandler,
    on_startup: Optional[LifecycleHook] = None,
    on_shutdown: Optional[LifecycleHook] = None,
) -> Starlette:
    async def agent_card_route(request: Request) -> JSONResponse:
        return JSONResponse(agent_card.model_dump(mode="json", by_alias=True, exclude_none=True))

    async def rpc_route(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception as exc:  # noqa: BLE001
            return _rpc_error(None, -32700, f"parse error: {exc}")

        try:
            rpc_request = a2a_types.SendMessageRequest.model_validate(body)
        except Exception as exc:  # noqa: BLE001
            return _rpc_error(body.get("id") if isinstance(body, dict) else None, -32600, f"invalid request: {exc}")

        message = rpc_request.params.message
        text = "\n".join(p.root.text for p in message.parts if p.root.kind == "text")
        try:
            payload = json.loads(text)
            skill_id = payload["skill"]
            skill_input = payload.get("input", {})
            trace_id = payload.get("trace_id")
        except Exception as exc:  # noqa: BLE001
            return _rpc_error(rpc_request.id, -32602, f"malformed skill request: {exc}")

        token = set_trace_id(trace_id) if trace_id else None
        try:
            log_event("specialist_request_received", agent=agent_card.name, tool=skill_id, input=skill_input)
            result = await handler(skill_id, skill_input)
            log_event(
                "specialist_request_finished" if "error" not in result else "specialist_request_failed",
                agent=agent_card.name, tool=skill_id, input=skill_input, result=result,
                error=result.get("error") if isinstance(result, dict) else None,
            )
        except Exception as exc:  # noqa: BLE001 - report cleanly, never crash the server
            result = {"error": str(exc)}
            log_event("specialist_request_failed", agent=agent_card.name, tool=skill_id, input=skill_input, error=str(exc))
        finally:
            if token is not None:
                reset_trace_id(token)

        reply = a2a_types.Message(
            messageId=str(uuid.uuid4()),
            role=a2a_types.Role.agent,
            parts=[a2a_types.Part(a2a_types.TextPart(text=json.dumps(result)))],
            taskId=message.task_id,
            contextId=message.context_id,
        )
        response = a2a_types.SendMessageSuccessResponse(id=rpc_request.id, result=reply)
        return JSONResponse(response.model_dump(mode="json", by_alias=True, exclude_none=True))

    @asynccontextmanager
    async def lifespan(app: Starlette):
        if on_startup is not None:
            await on_startup()
        try:
            yield
        finally:
            if on_shutdown is not None:
                await on_shutdown()

    return Starlette(
        routes=[
            Route("/", agent_card_route, methods=["GET"]),
            Route(AGENT_CARD_WELL_KNOWN_PATH, agent_card_route, methods=["GET"]),
            Route("/", rpc_route, methods=["POST"]),
        ],
        lifespan=lifespan,
    )
