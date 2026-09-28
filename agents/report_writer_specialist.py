"""A2A server: report-writer specialist.

A different concern from the security specialist -- pure Gemini synthesis,
no MCP dependency. Takes raw findings (breach results, CVE data, log
analysis output -- whatever text the orchestrator hands it) and turns them
into a structured report. Deliberately doesn't depend on the MCP server or
the security specialist, since this is a separate agent in the pipeline.

Run with: python -m agents.report_writer_specialist
"""

import os

from dotenv import load_dotenv

# pyrefly: ignore [missing-import]
import uvicorn
from a2a.compat.v0_3 import types as a2a_types

from agents.a2a_common import build_app
from agents.skills import REPORT_SKILLS
from client.audit import log_event
from client.llm_router import build_client, send_interaction

load_dotenv()

HOST = os.environ.get("REPORT_WRITER_HOST", "127.0.0.1")
PORT = int(os.environ.get("REPORT_WRITER_PORT", "8200"))
PUBLIC_URL = os.environ.get("REPORT_WRITER_URL", f"http://{HOST}:{PORT}")

_gemini_client = None


def _build_agent_card() -> a2a_types.AgentCard:
    skills = [
        a2a_types.AgentSkill(
            id=skill_id, name="Report Generation", description=info["description"], tags=["reporting"]
        )
        for skill_id, info in REPORT_SKILLS.items()
    ]
    return a2a_types.AgentCard(
        name="Report Writer",
        description="Turns raw security findings into a clean, structured, readable report.",
        url=PUBLIC_URL.rstrip("/") + "/",
        version="1.0.0",
        capabilities=a2a_types.AgentCapabilities(streaming=False),
        defaultInputModes=["text/plain"],
        defaultOutputModes=["text/plain"],
        skills=skills,
    )


async def _handle_skill(skill_id: str, skill_input: dict) -> dict:
    if skill_id != "report-generation":
        return {"error": f"unknown skill: {skill_id}"}
    if _gemini_client is None:
        return {"error": "report writer not configured (GEMINI_API_KEY missing at startup)"}

    target = skill_input.get("target", "unknown target")
    findings = skill_input.get("findings", "")
    prompt = (
        f"You are a security analyst. Write a concise, structured security report "
        f"for target: {target}.\n\n"
        f"Raw findings to incorporate:\n{findings}\n\n"
        f"Structure the report with: Summary, Findings (severity-ranked), Recommendations."
    )
    log_event("llm_call_started", agent="Report Writer", tool="report-generation", input=skill_input)
    try:
        interaction = await send_interaction(_gemini_client, prompt, tools=[], previous_interaction_id=None)
    except Exception as exc:  # noqa: BLE001
        log_event("llm_call_failed", agent="Report Writer", tool="report-generation", input=skill_input, error=str(exc))
        return {"error": f"Report generation failed: {exc}"}
    text = getattr(interaction, "output_text", None)
    if not text:
        text = "\n".join(
            getattr(step, "text", "") or ""
            for step in interaction.steps
            if getattr(step, "type", None) == "message"
        )
    result = {"report": text}
    log_event("llm_call_finished", agent="Report Writer", tool="report-generation", input=skill_input, result=result)
    return result


async def _startup() -> None:
    global _gemini_client
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY must be set for the report-writer specialist.")
    _gemini_client = build_client(api_key)


app = build_app(_build_agent_card(), _handle_skill, on_startup=_startup)

if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
