"""Thin wrapper around the Gemini API (Interactions API) for tool-use routing."""

from google import genai

MODEL = "gemini-3.7-flash"


def build_client(api_key: str) -> genai.Client:
    return genai.Client(api_key=api_key)


async def send_interaction(
    client: genai.Client,
    input_content,
    tools: list[dict],
    previous_interaction_id: str | None,
):
    """Send one turn to Gemini and return the raw Interaction response.

    `input_content` is either a plain string (first turn) or a list of
    function_result blocks (follow-up turns after a tool call). `tools`
    are Gemini-shaped function tool dicts, translated from the MCP tool
    schemas by the caller.
    """
    return await client.aio.interactions.create(
        model=MODEL,
        input=input_content,
        tools=tools,
        previous_interaction_id=previous_interaction_id,
    )
