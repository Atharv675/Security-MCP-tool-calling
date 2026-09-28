"""Configure Cognee once at startup with project settings.

Call ``configure_cognee()`` before any ``CogneeMemory.remember / recall`` call.
It is safe to call multiple times (idempotent guard via ``_configured`` flag in
``CogneeMemory``).

cognee 1.6.1 exposes a ``config`` **object** (not a callable) with explicit
setter methods::

    cognee.config.set_llm_provider(...)
    cognee.config.set_llm_model(...)
    cognee.config.set_llm_api_key(...)
    cognee.config.system_root_directory(...)
"""

import os
from pathlib import Path


def configure_cognee() -> None:
    """Wire Cognee to the Gemini LLM and a project-local storage directory.

    Reads from the same environment variables used everywhere else in this
    project so there is a single source of truth in ``.env``.
    """
    try:
        # pyrefly: ignore [missing-import]
        import cognee
    except ImportError as exc:
        raise RuntimeError(
            "Cognee is not installed. Run: pip install cognee"
        ) from exc

    # ── LLM provider ─────────────────────────────────────────────────────────
    llm_provider = os.environ.get("COGNEE_LLM_PROVIDER", "gemini")
    llm_model    = os.environ.get("COGNEE_LLM_MODEL",    "gemini-2.0-flash")
    api_key      = os.environ.get("GEMINI_API_KEY", "")

    # cognee.config is an object — use its explicit setter methods.
    cognee.config.set_llm_provider(llm_provider)
    cognee.config.set_llm_model(llm_model)
    cognee.config.set_llm_api_key(api_key)       # wires the GEMINI_API_KEY

    # ── Storage root ──────────────────────────────────────────────────────────
    # Keep cognee's graph/vector/relational DBs inside the project so they are
    # portable and not mixed with other projects in the system-wide default.
    data_root = Path(os.environ.get("COGNEE_DATA_ROOT", "./memory-data/cognee"))
    if not data_root.is_absolute():
        # Resolve relative to the project root (this file is memory/cognee_setup.py
        # so parent.parent == project root).
        data_root = (Path(__file__).resolve().parent.parent / data_root).resolve()
    data_root.mkdir(parents=True, exist_ok=True)

    # system_root_directory cascades to all internal DB paths.
    cognee.config.system_root_directory(str(data_root))
