"""Front-facing triage orchestrator.

Talks to the user, decides which parts of a query are security-tool work,
and delegates that work to A2A specialists (agents/security_specialist.py,
agents/report_writer_specialist.py) -- it never calls MCP tools directly
itself. Reuses client/agent.py's tool-use loop (run_query/resume_query)
unchanged: an A2APool (client/a2a_pool.py) stands in for the MCP session,
and is duck-type compatible with it, so the existing approval gate
(SENSITIVE_TOOLS) and resumable state machine apply to A2A delegation with
no changes there.

Chaining (security specialist -> report-writer) happens naturally: both
specialists' skills are exposed as tools in the same Gemini tool-use loop,
so "check X and give me a report" has Gemini call credential-breach-check
first, then (after approval) report-generation with those findings.

Run with: python -m agents.orchestrator
(the MCP server, security specialist, and report-writer specialist must
already be running -- see README)
"""

import asyncio
import json
import logging
import os
import sys

from dotenv import load_dotenv

from client.a2a_pool import A2APool, load_specialist_configs
from client.agent import resume_query, run_query
from client.llm_router import build_client

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("orchestrator")


async def _resolve_approvals_via_cli(pool: A2APool, gemini_client, tools: list[dict], result: dict) -> str:
    while result["status"] == "approval_needed":
        decisions: dict[str, bool] = {}
        for call in result["pending"]:
            answer = input(
                f"Approve delegating to specialist skill '{call['tool']}'({json.dumps(call['args'])})? [y/N]: "
            ).strip().lower()
            decisions[call["id"]] = answer == "y"
        result = await resume_query(pool, gemini_client, tools, result["resume_state"], decisions)
    return result["text"]


async def main():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("GEMINI_API_KEY is not set. Copy .env.example to .env and fill it in.")
        sys.exit(1)

    gemini_client = build_client(api_key)
    pool = A2APool(load_specialist_configs())

    try:
        await pool.connect()
    except Exception as exc:  # noqa: BLE001 - specialists must be reachable to start at all
        print(f"Could not reach one or more A2A specialists: {exc}")
        print("Make sure the security specialist and report-writer specialist are both running.")
        sys.exit(1)

    try:
        logger.info("Discovered %d specialist(s), %d skill(s)", len(pool.agent_cards), len(pool.tool_names))
        print(f"Connected to {len(pool.agent_cards)} specialist(s):")
        for card in pool.agent_cards:
            print(f"  - {card['name']} ({card['url']}): {', '.join(card['skills'])}")
        print("Type a query, or 'quit' to exit.")
        while True:
            try:
                user_query = input("\n> ").strip()
            except EOFError:
                break
            if not user_query or user_query.lower() in ("quit", "exit"):
                break

            result = await run_query(pool, gemini_client, pool.tools, user_query)
            trace_id = result["trace_id"]
            answer = await _resolve_approvals_via_cli(pool, gemini_client, pool.tools, result)
            print(f"\nTrace ID: {trace_id}\n{answer}")
    finally:
        await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
