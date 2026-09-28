"""Gemini-powered agent that discovers MCP tools/resources/prompts and routes queries.

Flow: user query -> Gemini decides which tool(s) to call -> agent executes via
MCP client -> tool result returned to Gemini -> Gemini produces a final answer.
Supports multiple sequential tool calls per query (e.g. hash -> breach_check).

Tools that make outbound calls (breach_check, cve_lookup) are gated behind a
human-in-the-loop approval step -- see SENSITIVE_TOOLS and the
run_query/resume_query state machine below. Local, side-effect-free tools
(password_strength, hash_password, verify_password_hash, log_analyzer) run
without confirmation.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Callable, Optional

from dotenv import load_dotenv

from client.audit import current_trace_id, log_event, new_trace_id, reset_trace_id, set_trace_id
from client.llm_router import build_client, send_interaction
from client.mcp_pool import MultiServerPool, load_server_configs
from client.mcp_utils import auth_headers, mcp_tools_to_gemini  # noqa: F401 - re-exported
from memory.settings import build_chat_memory

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("agent")

MAX_TOOL_ITERATIONS = 8

# Lazy singleton for the Obsidian-backed chat memory service.
# Built once on first use so the vault path is resolved after load_dotenv().
_chat_memory = None


def _get_chat_memory():
    """Return the ChatMemoryService singleton (Obsidian vault + Redis context)."""
    global _chat_memory
    if _chat_memory is None:
        _chat_memory = build_chat_memory()
    return _chat_memory

# Duck-typed: either a raw mcp.ClientSession (single-server) or a
# client.mcp_pool.MultiServerPool (multi-server) -- both expose async
# call_tool(name, args) / read_resource(uri) / get_prompt(name, args).
MCPSession = Any

# Tools that make outbound network calls -- gated behind explicit user approval.
# Checked against the UNQUALIFIED tool name (see _original_name below), so
# this still matches e.g. "srv2__breach_check" in multi-server mode.
SENSITIVE_TOOLS = {"breach_check", "cve_lookup"}

OnToolCall = Callable[[str, dict, str, bool], None]


def _original_name(session, exposed_name: str) -> str:
    """Map a (possibly server-namespaced) tool name back to its unqualified
    form for policy checks. A raw mcp.ClientSession (single-server, e.g. in
    tests) has no such mapping -- the name is already unqualified there."""
    getter = getattr(session, "original_name", None)
    return getter(exposed_name) if getter is not None else exposed_name


def _tool_result_to_text(result) -> str:
    parts = []
    for block in result.content:
        if hasattr(block, "text"):
            parts.append(block.text)
        else:
            parts.append(str(block))
    return "\n".join(parts) if parts else json.dumps({"result": "empty"})


def _interaction_output_text(interaction) -> str:
    if getattr(interaction, "output_text", None):
        return interaction.output_text
    texts = [
        getattr(step, "text", None)
        for step in interaction.steps
        if getattr(step, "type", None) == "message" and getattr(step, "text", None)
    ]
    return "\n".join(texts)


async def _execute_call(
    session: MCPSession, name: str, args: dict, call_id: str, on_tool_call: Optional[OnToolCall]
) -> dict:
    logger.info("Tool selected: %s | args: %s", name, json.dumps(args))
    log_event("tool_call_started", agent="orchestrator", tool=name, input=args, call_id=call_id)
    try:
        result = await session.call_tool(name, args)
        result_text = _tool_result_to_text(result)
        is_error = bool(getattr(result, "isError", False))
    except Exception as exc:  # noqa: BLE001 - surface as a tool error, don't crash the agent
        result_text = f"Tool call failed: {exc}"
        is_error = True
    logger.info("Raw result (%s): %s", name, result_text[:500])
    log_event(
        "tool_call_finished", agent="orchestrator", tool=name, input=args,
        result=result_text, error=result_text if is_error else None, call_id=call_id,
    )
    if on_tool_call is not None:
        on_tool_call(name, args, result_text, is_error)
    return {
        "type": "function_result",
        "name": name,
        "call_id": call_id,
        "result": [{"type": "text", "text": result_text}],
        "is_error": is_error,
    }


def _denied_result(name: str, args: dict, call_id: str, on_tool_call: Optional[OnToolCall]) -> dict:
    text = "Denied by user: this tool call was not approved."
    logger.info("Tool denied: %s | args: %s", name, json.dumps(args))
    log_event(
        "tool_call_denied", actor="user", agent="orchestrator", tool=name, input=args,
        result=text, error=text, approval_required=True, approval_given=False, call_id=call_id,
    )
    if on_tool_call is not None:
        on_tool_call(name, args, text, True)
    return {
        "type": "function_result",
        "name": name,
        "call_id": call_id,
        "result": [{"type": "text", "text": text}],
        "is_error": True,
    }


async def _advance(
    session: MCPSession,
    gemini_client,
    tools: list[dict],
    current_input,
    previous_interaction_id: Optional[str],
    on_tool_call: Optional[OnToolCall],
    iteration: int,
) -> dict:
    """Run one Gemini turn; execute non-sensitive calls; pause on sensitive ones."""
    log_event(
        "llm_interaction_started", agent="orchestrator", input=current_input,
        previous_interaction_id=previous_interaction_id,
    )
    try:
        interaction = await send_interaction(gemini_client, current_input, tools, previous_interaction_id)
    except Exception as exc:
        log_event("llm_interaction_failed", agent="orchestrator", input=current_input, error=str(exc))
        raise
    log_event("llm_interaction_finished", agent="orchestrator", result={"interaction_id": interaction.id})
    previous_interaction_id = interaction.id

    function_call_steps = [s for s in interaction.steps if s.type == "function_call"]
    logger.info("Gemini turn %d -> %d function call(s)", iteration, len(function_call_steps))
    log_event(
        "routing_decision", agent="orchestrator", input=current_input,
        result={"iteration": iteration, "selected_tools": [s.name for s in function_call_steps]},
    )

    if not function_call_steps:
        text = _interaction_output_text(interaction)
        log_event("final_answer", agent="orchestrator", result=text)
        return {"status": "answer", "text": text}

    executed_results = []
    pending = []
    for step in function_call_steps:
        if _original_name(session, step.name) in SENSITIVE_TOOLS:
            pending.append(step)
        else:
            executed_results.append(
                await _execute_call(session, step.name, step.arguments, step.id, on_tool_call)
            )

    if pending:
        pending_calls = [{"id": s.id, "tool": s.name, "args": s.arguments} for s in pending]
        for call in pending_calls:
            log_event(
                "approval_requested", actor="orchestrator", agent="orchestrator", tool=call["tool"],
                input=call["args"], approval_required=True, call_id=call["id"],
            )
        return {
            "status": "approval_needed",
            "pending": pending_calls,
            "resume_state": {
                "previous_interaction_id": previous_interaction_id,
                "executed_results": executed_results,
                "pending_calls": pending_calls,
                "trace_id": current_trace_id(),
            },
        }

    return {
        "status": "continue",
        "current_input": executed_results,
        "previous_interaction_id": previous_interaction_id,
    }


async def _loop(
    session: MCPSession,
    gemini_client,
    tools: list[dict],
    current_input,
    previous_interaction_id: Optional[str],
    on_tool_call: Optional[OnToolCall],
) -> dict:
    for iteration in range(MAX_TOOL_ITERATIONS):
        step_result = await _advance(
            session, gemini_client, tools, current_input, previous_interaction_id, on_tool_call, iteration
        )
        if step_result["status"] in ("answer", "approval_needed"):
            return step_result
        current_input = step_result["current_input"]
        previous_interaction_id = step_result["previous_interaction_id"]

    logger.warning("Hit MAX_TOOL_ITERATIONS without a final answer")
    return {"status": "answer", "text": "(stopped after too many tool calls without a final answer)"}


async def run_query(
    session: MCPSession,
    gemini_client,
    tools: list[dict],
    user_query: str,
    on_tool_call: Optional[OnToolCall] = None,
) -> dict:
    """Run one user query through the agentic tool-use loop.

    Returns {"status": "answer", "text": str} when done, or
    {"status": "approval_needed", "pending": [...], "resume_state": {...}}
    if a sensitive tool call is awaiting approval -- call resume_query with
    a decisions dict ({call_id: bool}) to continue.

    `on_tool_call`, if given, is invoked as (tool_name, args, result_text,
    is_error) after each tool call completes (approved, denied, or
    non-sensitive) -- used by the dashboard to capture a trace without
    duplicating this loop.

    Every query and final answer are written to the Obsidian vault so the full
    conversation is durably stored as human-readable Markdown notes.
    """
    trace_id = new_trace_id()
    token = set_trace_id(trace_id)
    try:
        log_event("request_received", actor="user", agent="orchestrator", input=user_query)

        # ── Obsidian: persist the user turn ──────────────────────────────────
        try:
            await _get_chat_memory().add_turn(trace_id, "user", user_query, trace_id=trace_id)
        except Exception as mem_exc:  # noqa: BLE001
            logger.warning("Obsidian vault write failed (user turn): %s", mem_exc)

        result = await _loop(session, gemini_client, tools, user_query, None, on_tool_call)
        result["trace_id"] = trace_id

        # ── Obsidian: persist the assistant answer ────────────────────────────
        if result.get("status") == "answer" and result.get("text"):
            try:
                await _get_chat_memory().add_turn(
                    trace_id, "assistant", result["text"], trace_id=trace_id
                )
            except Exception as mem_exc:  # noqa: BLE001
                logger.warning("Obsidian vault write failed (assistant turn): %s", mem_exc)

        return result
    finally:
        reset_trace_id(token)


async def resume_query(
    session: MCPSession,
    gemini_client,
    tools: list[dict],
    resume_state: dict,
    decisions: dict[str, bool],
    on_tool_call: Optional[OnToolCall] = None,
) -> dict:
    """Continue a query paused by run_query/resume_query, given approve/deny decisions.

    The final answer (after tool approval) is also written to the Obsidian vault.
    """
    trace_id = resume_state.get("trace_id") or new_trace_id()
    token = set_trace_id(trace_id)
    try:
        executed_results = list(resume_state["executed_results"])
        for call in resume_state["pending_calls"]:
            approved = decisions.get(call["id"], False)
            log_event(
                "approval_decision", actor="user", agent="orchestrator", tool=call["tool"],
                input=call["args"], approval_required=True, approval_given=approved, call_id=call["id"],
            )
            if approved:
                executed_results.append(
                    await _execute_call(session, call["tool"], call["args"], call["id"], on_tool_call)
                )
            else:
                executed_results.append(_denied_result(call["tool"], call["args"], call["id"], on_tool_call))

        result = await _loop(
            session, gemini_client, tools, executed_results, resume_state["previous_interaction_id"], on_tool_call
        )
        result["trace_id"] = trace_id

        # ── Obsidian: persist the assistant answer after approvals ────────────
        if result.get("status") == "answer" and result.get("text"):
            try:
                await _get_chat_memory().add_turn(
                    trace_id, "assistant", result["text"], trace_id=trace_id
                )
            except Exception as mem_exc:  # noqa: BLE001
                logger.warning("Obsidian vault write failed (resume answer): %s", mem_exc)

        return result
    finally:
        reset_trace_id(token)


async def generate_report(
    session: MCPSession,
    gemini_client,
    tools: list[dict],
    target: str,
    on_tool_call: Optional[OnToolCall] = None,
) -> dict:
    """Generate a security report for `target` using the scan history Resource
    and the generate_security_report Prompt, then let Gemini write it up."""
    trace_id = new_trace_id()
    token = set_trace_id(trace_id)
    try:
        log_event("request_received", actor="user", agent="orchestrator", input={"report_target": target})
        log_event("resource_read_started", agent="orchestrator", input={"uri": "scan://history"})
        history = await session.read_resource("scan://history")
        findings_text = history.contents[0].text if history.contents else "[]"
        log_event("resource_read_finished", agent="orchestrator", input={"uri": "scan://history"}, result=findings_text)

        prompt_args = {"target": target, "findings": findings_text}
        log_event("prompt_fetch_started", agent="orchestrator", input={"name": "generate_security_report", "args": prompt_args})
        prompt_result = await session.get_prompt("generate_security_report", prompt_args)
        prompt_text = prompt_result.messages[0].content.text
        log_event("prompt_fetch_finished", agent="orchestrator", input={"name": "generate_security_report"}, result=prompt_text)
        result = await _loop(session, gemini_client, tools, prompt_text, None, on_tool_call)
        result["trace_id"] = trace_id
        return result
    except Exception as exc:
        log_event("request_failed", agent="orchestrator", error=str(exc))
        raise
    finally:
        reset_trace_id(token)


async def _resolve_approvals_via_cli(
    session: MCPSession, gemini_client, tools: list[dict], result: dict
) -> str:
    while result["status"] == "approval_needed":
        decisions: dict[str, bool] = {}
        for call in result["pending"]:
            answer = input(
                f"Approve {call['tool']}({json.dumps(call['args'])})? [y/N]: "
            ).strip().lower()
            decisions[call["id"]] = answer == "y"
        result = await resume_query(session, gemini_client, tools, result["resume_state"], decisions)
    return result["text"]


async def main():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("GEMINI_API_KEY is not set. Copy .env.example to .env and fill it in.")
        sys.exit(1)

    configs = load_server_configs()
    missing_token = [cfg.server_id for cfg in configs if not cfg.token]
    if missing_token:
        print(
            f"No auth token configured for: {', '.join(missing_token)}. Set MCP_AUTH_TOKEN "
            "(single-server) or MCP_AUTH_TOKENS (multi-server) in .env."
        )
        sys.exit(1)

    gemini_client = build_client(api_key)
    pool = MultiServerPool(configs)
    await pool.connect()
    try:
        tools = pool.tools
        logger.info(
            "Discovered %d tools across %d server(s): %s", len(tools), len(configs), pool.tool_names
        )
        logger.info("Discovered %d resources, %d prompts", len(pool.resources), len(pool.prompts))

        print(f"Connected to {len(configs)} server(s):")
        for cfg in configs:
            print(f"  - {cfg.server_id}: {cfg.url}")
        print("Tools:", ", ".join(pool.tool_names))
        print("Resources:", ", ".join(f"{r['server_id']}:{r['uri']}" for r in pool.resources) or "(none)")
        print("Prompts:", ", ".join(f"{p['server_id']}:{p['name']}" for p in pool.prompts) or "(none)")
        print("Type a query, 'report <target>' for a security report, or 'quit' to exit.")
        while True:
            try:
                user_query = input("\n> ").strip()
            except EOFError:
                break
            if not user_query or user_query.lower() in ("quit", "exit"):
                break

            if user_query.lower().startswith("report "):
                target = user_query[len("report ") :].strip()
                result = await generate_report(pool, gemini_client, tools, target)
            else:
                result = await run_query(pool, gemini_client, tools, user_query)

            trace_id = result.get("trace_id", result.get("resume_state", {}).get("trace_id"))
            answer = await _resolve_approvals_via_cli(pool, gemini_client, tools, result)
            print(f"\nTrace ID: {trace_id}\n{answer}")
    finally:
        await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
