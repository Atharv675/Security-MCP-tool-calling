"""Connect to one or more MCP servers and present them as a single router.

Tool names are only namespaced (`{server_id}__{tool_name}`) when more than
one server is configured -- single-server mode exposes the exact same
unqualified tool names as before (breach_check, cve_lookup, ...), so
existing behavior, SENSITIVE_TOOLS, and tests are unaffected.

Config: MCP_SERVER_URLS (comma-separated) + MCP_AUTH_TOKENS (comma-separated,
matched by position; blank/short falls back to MCP_AUTH_TOKEN). If
MCP_SERVER_URLS isn't set, falls back to the single-server MCP_SERVER_URL /
MCP_AUTH_TOKEN env vars.
"""

import contextlib
import os
from dataclasses import dataclass, field

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from client.mcp_utils import auth_headers, mcp_tool_to_gemini


@dataclass
class ServerConfig:
    server_id: str
    url: str
    token: str = ""


def load_server_configs() -> list[ServerConfig]:
    urls_env = os.environ.get("MCP_SERVER_URLS", "").strip()
    if urls_env:
        urls = [u.strip() for u in urls_env.split(",") if u.strip()]
    else:
        urls = [os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp/")]

    tokens_env = os.environ.get("MCP_AUTH_TOKENS", "")
    tokens = [t.strip() for t in tokens_env.split(",")] if tokens_env else []
    default_token = os.environ.get("MCP_AUTH_TOKEN", "")

    return [
        ServerConfig(
            server_id=f"srv{i + 1}",
            url=url,
            token=(tokens[i] if i < len(tokens) and tokens[i] else default_token),
        )
        for i, url in enumerate(urls)
    ]


@dataclass
class MultiServerPool:
    """Aggregates tools/resources/prompts across one or more MCP servers.

    Duck-type compatible with a single `mcp.ClientSession` for the three
    operations the agent loop needs: call_tool(name, args), read_resource(uri),
    get_prompt(name, args). Use `.original_name()` to map a (possibly
    namespaced) tool name back to its unqualified form for policy checks
    (e.g. SENSITIVE_TOOLS) -- a raw ClientSession has no such method, so
    callers use getattr(session, "original_name", lambda n: n) to stay
    compatible with both.
    """

    configs: list[ServerConfig]
    tools: list[dict] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    prompts: list[dict] = field(default_factory=list)

    def __post_init__(self):
        self._stack: contextlib.AsyncExitStack | None = None
        self._sessions: dict[str, ClientSession] = {}
        # exposed (possibly namespaced) tool name -> (server_id, original name)
        self._routes: dict[str, tuple[str, str]] = {}

    @property
    def multi(self) -> bool:
        return len(self.configs) > 1

    async def connect(self) -> None:
        self._stack = contextlib.AsyncExitStack()
        for cfg in self.configs:
            read, write, _ = await self._stack.enter_async_context(
                streamablehttp_client(cfg.url, headers=auth_headers(cfg.token))
            )
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self._sessions[cfg.server_id] = session

            for tool in (await session.list_tools()).tools:
                exposed = tool.name if not self.multi else f"{cfg.server_id}__{tool.name}"
                self._routes[exposed] = (cfg.server_id, tool.name)
                self.tools.append(mcp_tool_to_gemini(tool, name_override=exposed))
                self.tool_names.append(exposed)

            for r in (await session.list_resources()).resources:
                self.resources.append(
                    {"server_id": cfg.server_id, "uri": str(r.uri), "name": r.name, "description": r.description}
                )

            for p in (await session.list_prompts()).prompts:
                self.prompts.append({"server_id": cfg.server_id, "name": p.name, "description": p.description})

    def original_name(self, exposed_name: str) -> str:
        route = self._routes.get(exposed_name)
        return route[1] if route else exposed_name

    async def call_tool(self, exposed_name: str, args: dict):
        route = self._routes.get(exposed_name)
        if route is None:
            raise ValueError(f"unknown tool: {exposed_name}")
        server_id, original_name = route
        return await self._sessions[server_id].call_tool(original_name, args)

    async def read_resource(self, uri: str):
        """Try each connected server in order; first one that has the resource wins."""
        last_error: Exception | None = None
        for session in self._sessions.values():
            try:
                return await session.read_resource(uri)
            except Exception as exc:  # noqa: BLE001 - fall through to the next server
                last_error = exc
        raise last_error or ValueError(f"resource not found on any server: {uri}")

    async def get_prompt(self, name: str, args: dict):
        """Try each connected server in order; first one that has the prompt wins."""
        last_error: Exception | None = None
        for session in self._sessions.values():
            try:
                return await session.get_prompt(name, args)
            except Exception as exc:  # noqa: BLE001 - fall through to the next server
                last_error = exc
        raise last_error or ValueError(f"prompt not found on any server: {name}")

    async def aclose(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
