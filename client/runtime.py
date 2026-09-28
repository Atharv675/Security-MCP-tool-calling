"""Persistent agent runtime for the Streamlit dashboard.

Streamlit reruns the whole script on every interaction, so the MCP
connection(s) (and the Gemini client) run on a dedicated background thread
with its own asyncio event loop, kept alive in `st.session_state` across
reruns instead of reconnecting per query.

Sensitive-tool approval works by returning early instead of blocking: `ask`
and `resume` return a "approval_needed" status the same shape run_query /
resume_query produce in client/agent.py, letting the dashboard render an
Approve/Deny UI and resume on the next Streamlit rerun (button click)
without needing to block the Streamlit main thread mid-query.

Multi-server: if MCP_SERVER_URLS is set in the environment, it's used
(supporting more than one MCP server, tool names auto-namespaced -- see
client/mcp_pool.py). Otherwise falls back to the single `mcp_url`/`api_key`
passed in from the dashboard's sidebar fields, preserving the original
single-server UX.
"""

import asyncio
import os
import threading

from client.agent import generate_report, resume_query, run_query
from client.llm_router import build_client
from client.mcp_pool import MultiServerPool, ServerConfig, load_server_configs

# Gemini's Interactions API has been observed taking anywhere from a few
# seconds to several minutes per call, and a query can involve several
# turns (tool calls) -- so this needs to be generous, not a short UI timeout.
_RUN_TIMEOUT_SECONDS = 600


class AgentRuntime:
    def __init__(self, mcp_url: str, api_key: str):
        self.mcp_url = mcp_url
        self.tools: list[dict] = []
        self.tool_names: list[str] = []
        self.resources: list[dict] = []
        self.prompts: list[dict] = []
        self.server_configs: list[ServerConfig] = []

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

        self._pool: MultiServerPool | None = None
        self._client = build_client(api_key)

        future = asyncio.run_coroutine_threadsafe(self._connect(), self._loop)
        future.result(timeout=30)

    async def _connect(self) -> None:
        if os.environ.get("MCP_SERVER_URLS", "").strip():
            configs = load_server_configs()
        else:
            configs = [ServerConfig(server_id="srv1", url=self.mcp_url, token=os.environ.get("MCP_AUTH_TOKEN", ""))]
        self.server_configs = configs

        self._pool = MultiServerPool(configs)
        await self._pool.connect()

        self.tools = self._pool.tools
        self.tool_names = self._pool.tool_names
        self.resources = self._pool.resources
        self.prompts = self._pool.prompts

    def _run(self, coro) -> dict:
        """Run a coroutine on the background loop and shape its result for the UI."""
        trace: list[dict] = []

        def _on_tool_call(name: str, args: dict, result: str, is_error: bool) -> None:
            trace.append({"tool": name, "args": args, "result": result, "is_error": is_error})

        future = asyncio.run_coroutine_threadsafe(coro(_on_tool_call), self._loop)
        try:
            result = future.result(timeout=_RUN_TIMEOUT_SECONDS)
        except TimeoutError:
            future.cancel()
            return {
                "status": "answer",
                "text": (
                    f"Timed out after {_RUN_TIMEOUT_SECONDS}s waiting on Gemini/MCP. "
                    "Gemini's API has been slow/rate-limited -- try again shortly."
                ),
                "trace": trace,
            }
        result["trace"] = trace
        return result

    def ask(self, query: str) -> dict:
        """Run one query. Returns a dict with "status": "answer" (+ "text")
        or "approval_needed" (+ "pending", "resume_state"), plus "trace"."""
        return self._run(
            lambda on_tool_call: run_query(self._pool, self._client, self.tools, query, on_tool_call)
        )

    def resume(self, resume_state: dict, decisions: dict[str, bool]) -> dict:
        """Continue a query paused by ask()/resume() with approve/deny decisions."""
        return self._run(
            lambda on_tool_call: resume_query(
                self._pool, self._client, self.tools, resume_state, decisions, on_tool_call
            )
        )

    def report(self, target: str) -> dict:
        """Generate a security report for `target` via the scan history
        Resource + generate_security_report Prompt."""
        return self._run(
            lambda on_tool_call: generate_report(
                self._pool, self._client, self.tools, target, on_tool_call
            )
        )

    def close(self) -> None:
        async def _close() -> None:
            if self._pool is not None:
                await self._pool.aclose()

        try:
            asyncio.run_coroutine_threadsafe(_close(), self._loop).result(timeout=10)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
