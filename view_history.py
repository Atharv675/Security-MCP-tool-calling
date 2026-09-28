"""Quick script: print the raw scan history from the running MCP server."""

import asyncio
import json
import os

from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

load_dotenv()

MCP_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp/")
TOKEN = os.environ["MCP_AUTH_TOKEN"]


async def main():
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with streamablehttp_client(MCP_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.read_resource("scan://history")
            history = json.loads(result.contents[0].text)
            print(f"{len(history)} entries (most recent first):\n")
            for entry in history:
                print(json.dumps(entry, indent=2))


asyncio.run(main())
