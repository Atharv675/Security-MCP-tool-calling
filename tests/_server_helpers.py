"""Shared helpers for tests that spin up server.main as a subprocess."""

import os
import subprocess
import sys
import time

import httpx


def start_server(port: str, token: str, host: str = "127.0.0.1") -> subprocess.Popen:
    env = {**os.environ, "MCP_PORT": port, "MCP_HOST": host, "MCP_AUTH_TOKEN": token}
    return subprocess.Popen(
        [sys.executable, "-m", "server.main"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def wait_until_ready(url: str, timeout: float = 20.0) -> None:
    """Poll until the server accepts connections, instead of guessing a fixed
    sleep -- starting one (or several, concurrently) Python subprocesses that
    import FastMCP can take a variable amount of time under load."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            # Any HTTP response (even a 401/307) means the port is accepting
            # connections and FastMCP has finished starting up.
            httpx.get(url, timeout=1.0)
            return
        except httpx.HTTPError:
            time.sleep(0.25)
    raise RuntimeError(f"server at {url} did not become ready within {timeout}s")
