"""Streamlit dashboard for the MCP security toolkit agent.

Same flow as client/agent.py (query -> Gemini picks tool(s) -> MCP call ->
final answer), but as a chat UI with a visible per-turn tool-call trace, a
sidebar listing discovered Resources/Prompts, a report-generation panel, and
an Approve/Deny UI for sensitive tool calls. Run with:

    streamlit run client/dashboard.py
"""

import os
import sys
from pathlib import Path

# `streamlit run` puts this file's own directory (client/) on sys.path, not
# the project root, so `client.runtime` can't be found as a package unless
# the root is added explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# pyrefly: ignore [missing-import]
import streamlit as st
from dotenv import load_dotenv

from client.runtime import AgentRuntime

load_dotenv()

st.set_page_config(page_title="MCP Security Toolkit", page_icon="🛡️", layout="wide")

DEFAULT_MCP_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp/")


def _get_runtime(mcp_url: str, api_key: str, auth_token: str) -> AgentRuntime:
    cache_key = (mcp_url, api_key, auth_token)
    if st.session_state.get("_runtime_key") != cache_key:
        old = st.session_state.get("runtime")
        if old is not None:
            old.close()
        os.environ["MCP_AUTH_TOKEN"] = auth_token
        st.session_state.runtime = AgentRuntime(mcp_url, api_key)
        st.session_state._runtime_key = cache_key
    return st.session_state.runtime


def _render_trace(trace: list[dict]) -> None:
    if not trace:
        return
    with st.expander(f"Tool calls ({len(trace)})"):
        for step in trace:
            icon = "❌" if step["is_error"] else "✅"
            st.markdown(f"**{icon} `{step['tool']}`**")
            st.json(step["args"])
            st.code(step["result"], language="json")


def _handle_result(label: str, result: dict) -> None:
    """Store the result: either finish the turn, or park it awaiting approval."""
    if result["status"] == "approval_needed":
        st.session_state.pending = {
            "label": label,
            "pending": result["pending"],
            "resume_state": result["resume_state"],
            "trace": result["trace"],
            "trace_id": result.get("trace_id"),
        }
    else:
        st.session_state.chat_history.append(
            {"role": "assistant", "content": result["text"], "trace": result["trace"], "trace_id": result.get("trace_id")}
        )
        st.session_state.pending = None


st.title("🛡️ MCP Security Toolkit")
st.caption("Ask about password strength, hashing, breach checks, CVEs, or log analysis.")

with st.sidebar:
    st.header("Connection")
    mcp_url = st.text_input("MCP server URL", value=DEFAULT_MCP_URL)
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        api_key = st.text_input("GEMINI_API_KEY", type="password")
    auth_token = os.environ.get("MCP_AUTH_TOKEN", "")
    if not auth_token:
        auth_token = st.text_input("MCP_AUTH_TOKEN", type="password")

    if not api_key or not auth_token:
        st.warning("Set GEMINI_API_KEY and MCP_AUTH_TOKEN in .env, or paste them above, to connect.")
        st.stop()

    if os.environ.get("MCP_SERVER_URLS", "").strip():
        st.caption("MCP_SERVER_URLS is set — multi-server mode active; the URL field above is ignored.")

    try:
        runtime = _get_runtime(mcp_url, api_key, auth_token)
    except Exception as exc:  # noqa: BLE001 - surface connection failures in the UI
        st.error(f"Could not connect to MCP server(s): {exc}")
        st.stop()

    st.success(f"Connected — {len(runtime.server_configs)} server(s), {len(runtime.tool_names)} tools discovered")

    st.subheader("Servers")
    for cfg in runtime.server_configs:
        st.markdown(f"- `{cfg.server_id}` — {cfg.url}")

    st.subheader("Tools")
    for name in runtime.tool_names:
        st.markdown(f"- `{name}`")

    st.subheader("Resources")
    for r in runtime.resources:
        st.markdown(f"- `{r['server_id']}` · `{r['uri']}` — {r['description'] or r['name']}")

    st.subheader("Prompts")
    for p in runtime.prompts:
        st.markdown(f"- `{p['server_id']}` · `{p['name']}` — {p['description'] or ''}")

    st.divider()
    st.subheader("Generate security report")
    report_target = st.text_input("Target", placeholder="e.g. example.com")
    if st.button("Generate report") and report_target:
        st.session_state.chat_history.append(
            {"role": "user", "content": f"[report] {report_target}"}
        )
        with st.spinner("Generating report…"):
            result = runtime.report(report_target)
        _handle_result(f"[report] {report_target}", result)
        st.rerun()

    st.divider()
    if st.button("Clear chat"):
        st.session_state.chat_history = []
        st.session_state.pending = None
        st.rerun()

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "pending" not in st.session_state:
    st.session_state.pending = None

for turn in st.session_state.chat_history:
    with st.chat_message(turn["role"]):
        st.markdown(turn["content"])
        if turn.get("trace_id"):
            st.caption(f"Trace ID: `{turn['trace_id']}`")
        _render_trace(turn.get("trace") or [])

pending = st.session_state.pending
if pending:
    with st.chat_message("assistant"):
        st.warning(
            f"Approval needed for {len(pending['pending'])} tool call(s) before continuing "
            f"with: *{pending['label']}*"
        )
        if pending.get("trace_id"):
            st.caption(f"Trace ID: `{pending['trace_id']}`")
        decisions: dict[str, bool] = {}
        for call in pending["pending"]:
            decisions[call["id"]] = st.checkbox(
                f"Approve `{call['tool']}`({call['args']})", value=False, key=f"approve_{call['id']}"
            )

        col1, col2, col3 = st.columns(3)
        approve_all = col1.button("Approve all")
        deny_all = col2.button("Deny all")
        continue_clicked = col3.button("Continue with selection")

        if approve_all or deny_all or continue_clicked:
            if approve_all:
                decisions = {c["id"]: True for c in pending["pending"]}
            elif deny_all:
                decisions = {c["id"]: False for c in pending["pending"]}
            with st.spinner("Resuming…"):
                result = runtime.resume(pending["resume_state"], decisions)
            result["trace"] = pending["trace"] + result["trace"]
            _handle_result(pending["label"], result)
            st.rerun()

user_query = st.chat_input("Ask a security question…", disabled=bool(pending))
if user_query:
    st.session_state.chat_history.append({"role": "user", "content": user_query})
    with st.chat_message("user"):
        st.markdown(user_query)

    with st.spinner("Thinking…"):
        try:
            result = runtime.ask(user_query)
        except Exception as exc:  # noqa: BLE001 - show the error instead of crashing the app
            result = {"status": "answer", "text": f"Error while processing query: {exc}", "trace": []}
    _handle_result(user_query, result)
    st.rerun()
