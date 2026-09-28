# MCP Security Toolkit

A cybersecurity MCP (Model Context Protocol) server, built with [FastMCP](https://github.com/jlowin/fastmcp), plus a Gemini-powered agent client that discovers its tools dynamically and routes natural-language queries to them.

Now with a **dual-layer persistent memory system**: Redis + Obsidian Markdown for chat memory, and Redis + Cognee semantic graph + SQLite + content-addressed artifacts for agent memory.

```
mcp-security-toolkit/
├── server/
│   ├── main.py                      # FastMCP server: tools, auth, resource, prompt
│   ├── config.py                    # env vars via pydantic-settings
│   └── tools/
│       ├── password.py              # strength check, entropy scoring
│       ├── hashing.py               # MD5/SHA1/SHA256/bcrypt hash + verify
│       ├── breach_check.py          # HIBP Pwned Passwords API (k-anonymity)
│       ├── cve_lookup.py            # NVD API CVE search by keyword/CVE-ID
│       ├── log_analyzer.py          # parse log file/text, flag suspicious patterns
│       ├── scan_history.py          # in-memory scan log, exposed as a Resource
│       └── rate_limit.py            # sliding-window limiter used by breach_check/cve_lookup
├── client/
│   ├── agent.py                     # agentic loop, approval gate, Obsidian chat memory, CLI
│   ├── mcp_pool.py                  # multi-server connection pool (tool merge/namespacing)
│   ├── mcp_utils.py                 # MCP<->Gemini schema conversion
│   ├── a2a_pool.py                  # A2A specialist connection pool
│   ├── llm_router.py                # Gemini API wrapper (Interactions API)
│   ├── runtime.py                   # persistent MCP/Gemini connection for the dashboard
│   ├── audit.py                     # append-only structured audit logging
│   ├── audit_query.py               # CLI for inspecting audit records
│   └── dashboard.py                 # Streamlit chat UI
├── agents/                          # A2A multi-agent pipeline
│   ├── skills.py                    # skill id -> MCP tool + JSON Schema
│   ├── a2a_common.py                # shared Starlette/A2A JSON-RPC server plumbing
│   ├── security_specialist.py       # A2A server: wraps MCP tools as skills
│   ├── report_writer_specialist.py  # A2A server: findings -> structured report
│   └── orchestrator.py              # front-facing triage agent, delegates over A2A
├── memory/                          # ✨ NEW — dual-layer persistent memory system
│   ├── __init__.py                  # re-exports build_chat_memory / build_agent_memory
│   ├── settings.py                  # environment-configured factory functions
│   ├── chat_memory.py               # ChatMemoryService: Redis + ObsidianVault
│   ├── agent_memory.py              # AgentMemoryService: Redis + Cognee + SQLite + artifacts
│   ├── redis_store.py               # Redis async adapter with TTL and bounded lists
│   └── cognee_setup.py              # ✨ NEW — configure Cognee with Gemini key + storage path
├── MCP Memory/                      # ✨ NEW — Obsidian vault (chat memory store)
│   ├── .obsidian/                   # Obsidian app configuration (auto-managed)
│   ├── Chats/                       # auto-created: one .md file per conversation
│   └── Knowledge/                   # auto-created: manually curated fact notes
├── memory-data/                     # ✨ NEW — runtime data (git-ignored)
│   ├── cognee/                      # Cognee graph/vector/relational databases
│   ├── executions.sqlite3           # structured agent execution records
│   └── artifacts/                   # SHA-256 content-addressed JSON tool outputs
├── tests/
│   ├── test_e2e.py
│   ├── test_auth.py
│   ├── test_multi_server.py
│   ├── test_a2a_pipeline.py
│   └── test_memory_architecture.py  # ✨ NEW — memory layer architecture tests
├── import_history_to_obsidian.py    # ✨ NEW — migrate audit.jsonl history to Obsidian
├── docker-compose.memory.yml        # ✨ NEW — Redis, PostgreSQL, MinIO services
├── requirements.txt
├── .env.example
└── README.md
```

---

## Quick Start (Complete Steps)

### Prerequisites

- Python **3.11+**
- [Obsidian](https://obsidian.md) desktop app (free) — already installed in `MCP Memory/`
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) — for Redis (required for memory)
- A **Gemini API key** from [Google AI Studio](https://aistudio.google.com/)

---

### Step 1 — Create and activate the virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate
```

---

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

> This also installs `cognee` (semantic memory) and all its dependencies.

---

### Step 3 — Configure environment variables

The `.env` file is already set up in this project. Review it and confirm all keys:

```bash
# Open .env and verify these are set:
GEMINI_API_KEY=<your-key>          # Required: Gemini API (also used by Cognee)
MCP_AUTH_TOKEN=<generated-token>   # Required: bearer token for MCP server

# Memory system (already configured to use MCP Memory/ vault):
OBSIDIAN_VAULT_PATH=./MCP Memory   # Points to the Obsidian vault folder
AGENT_MEMORY_COGNEE_ENABLED=true   # Enables Cognee semantic memory
COGNEE_LLM_PROVIDER=gemini
COGNEE_LLM_MODEL=gemini-2.0-flash
```

To generate a new auth token:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

### Step 4 — Start Redis (required for memory)

Redis is the working memory for both chat and agent memory layers.

**Option A — Docker (recommended):**
```bash
docker compose -f docker-compose.memory.yml up -d redis
```

**Option B — Local Redis on Windows:**
Download and run [Redis for Windows](https://github.com/microsoftarchive/redis/releases) or use WSL2.

Verify Redis is running:
```bash
python -c "import redis; r = redis.from_url('redis://127.0.0.1:6379/0'); print(r.ping())"
```

---

### Step 5 — Start the MCP server

```bash
python -m server.main
```

Starts on `http://0.0.0.0:8005/mcp/` (port 8005, set in `.env`). The server **refuses to start** if `MCP_AUTH_TOKEN` is not set.

---

### Step 6 — Run the agent (CLI)

In a second terminal (with `.venv` activated):

```bash
python -m client.agent
```

On startup the agent:
1. Connects to the MCP server and discovers tools dynamically
2. Initialises the **Obsidian vault** (`MCP Memory/Chats/`) for chat memory
3. Every query + answer is automatically saved as a Markdown note in Obsidian

Type a query or `quit` to exit.

---

### Step 7 — Run the dashboard (optional UI)

```bash
streamlit run client/dashboard.py
```

Opens at `http://localhost:8501`. Features a chat UI, tool-call trace panel, approval checkboxes for sensitive tools, and a security report generator.

---

### Step 8 — Open your Obsidian vault (optional, to view chat history)

1. Open the **Obsidian** desktop app
2. Click **Open folder as vault**
3. Select the `MCP Memory/` folder inside this project
4. Browse `Chats/` — each conversation appears as a dated Markdown file

---

### Import existing chat history (one-time)

If you have an existing `audit.jsonl` from previous runs, import it into Obsidian:

```bash
# Preview first (no files written)
python import_history_to_obsidian.py --dry-run

# Import all conversations
python import_history_to_obsidian.py

# Re-import / overwrite existing notes
python import_history_to_obsidian.py --overwrite

# Custom paths
python import_history_to_obsidian.py --audit /path/to/audit.jsonl --vault /path/to/vault
```

---

### Run the A2A multi-agent pipeline (optional, 4 terminals)

```bash
# Terminal 1
python -m server.main

# Terminal 2
python -m agents.security_specialist

# Terminal 3
python -m agents.report_writer_specialist

# Terminal 4 — talk to this
python -m agents.orchestrator
```

---

### Run tests

```bash
pytest tests/ -v
```

---

## Persistent Memory System

This project has two intentionally separate memory architectures. They do **not** treat logs as memory or use semantic memory as an audit trail.

| Architecture | Short-term / working memory | Long-term memory | Durable records |
|---|---|---|---|
| **LLM chat** | Redis context window (TTL) | **Obsidian vault** — human-readable Markdown conversations in `MCP Memory/Chats/` | Existing audit JSONL remains the approval/audit record |
| **AI agent** | Redis bounded run timeline | **Cognee** — semantic, episodic, relationship-aware graph memory | SQLite execution-event store + SHA-256 content-addressed JSON artifact files |

### How it works end-to-end

```
User query
    │
    ▼
client/agent.py (run_query)
    ├─► ObsidianVault.append_turn()  ──► MCP Memory/Chats/YYYY-MM-DD-<trace>.md
    ├─► Redis.append_event()         ──► expiring context window (TTL: 1h)
    │
    ├─► [tool calls via MCP]
    │       └─► AgentMemoryService.record_tool_result()
    │               ├─► SQLite (executions.sqlite3)
    │               ├─► FileArtifactStore (memory-data/artifacts/<sha256>.json)
    │               ├─► Redis working state
    │               └─► Cognee.remember()  ──► semantic graph (memory-data/cognee/)
    │
    └─► ObsidianVault.append_turn()  ──► assistant answer appended to same note
```

### Environment variables

```bash
# Redis (working memory for both layers)
MEMORY_REDIS_URL=redis://127.0.0.1:6379/0
CHAT_MEMORY_REDIS_TTL_SECONDS=3600          # 1 hour context window

# Obsidian (chat long-term memory)
OBSIDIAN_VAULT_PATH=./MCP Memory            # ← points to your installed vault

# Cognee (agent semantic memory)
AGENT_MEMORY_COGNEE_ENABLED=true
COGNEE_LLM_PROVIDER=gemini
COGNEE_LLM_MODEL=gemini-2.0-flash
COGNEE_DATA_ROOT=./memory-data/cognee       # graph/vector/relational DB storage

# SQLite + artifacts (agent structured records)
AGENT_EXECUTION_DB_PATH=./memory-data/executions.sqlite3
AGENT_ARTIFACT_ROOT=./memory-data/artifacts
```

### Key files added

| File | Purpose |
|------|---------|
| `memory/chat_memory.py` | `ChatMemoryService` + `ObsidianVault` — appends every chat turn to both Redis and a `.md` note |
| `memory/agent_memory.py` | `AgentMemoryService` + `CogneeMemory` — coordinates Redis, Cognee, SQLite, and artifact store |
| `memory/redis_store.py` | Async Redis adapter with TTL and bounded event lists |
| `memory/settings.py` | Factory functions: `build_chat_memory()` / `build_agent_memory()` — read all config from `.env` |
| `memory/cognee_setup.py` | Configures Cognee 1.6.1 with Gemini API key + project-local storage via setter methods |
| `import_history_to_obsidian.py` | One-shot script to import `audit.jsonl` history into the Obsidian vault |
| `docker-compose.memory.yml` | Docker services: Redis, PostgreSQL (production upgrade path), MinIO (artifact store upgrade path) |

### Cognee API key wiring (Cognee 1.6.1)

Cognee is configured via setter methods on the `cognee.config` object (not a callable):

```python
cognee.config.set_llm_provider("gemini")
cognee.config.set_llm_model("gemini-2.0-flash")
cognee.config.set_llm_api_key(os.environ["GEMINI_API_KEY"])   # reuses your existing key
cognee.config.system_root_directory("./memory-data/cognee")
```

This happens automatically on first agent run via `memory/cognee_setup.py`. No separate Cognee API key is needed — it reuses `GEMINI_API_KEY` from `.env`.

---

## Running the server

```bash
python -m server.main
```

Starts a FastMCP server on Streamable HTTP, `http://0.0.0.0:8005/mcp/` (override with `MCP_HOST`/`MCP_PORT` in `.env`). **The server refuses to start if `MCP_AUTH_TOKEN` isn't set.**

## Running the client

In a second terminal, with the server running:

```bash
python -m client.agent
```

On startup the agent connects to the MCP server, calls `list_tools()` to discover tools dynamically, and initialises the Obsidian vault. Type a query, get an answer.

### Example queries

- `Is the password 'Tr0ub4dor&3' strong?`
- `Give me the bcrypt hash of 'hunter2'`
- `Has the password 'password123' been breached?`
- `Is 'password123' secure, and has it been breached?` — chains `password_strength` then `breach_check`
- `What is CVE-2021-44228?`
- `Search for vulnerabilities related to log4j`
- `Analyze this log for suspicious activity: <paste log text>`
- `report example.com` — generates a security report from recent scan history

Every request is assigned a UUID trace ID shown with the answer. The append-only JSONL audit trail (`audit.jsonl`) records routing decisions, tool invocations, approval events, and final answers. Each conversation is **also saved to Obsidian** automatically.

### Audit queries

```bash
python -m client.audit_query timeline <trace-id>     # complete chronological chain
python -m client.audit_query tools <trace-id>        # tool/delegation-related records
python -m client.audit_query denied-today            # count of denied approvals today
```

## Running the dashboard

```bash
streamlit run client/dashboard.py
```

Opens at `http://localhost:8501`. The sidebar shows connection status, discovered tools/resources/prompts, and a security report panel. Each reply has an expandable tool-calls trace. Approval for sensitive tools renders as checkboxes.

## Multi-server support

```bash
MCP_SERVER_URLS=http://127.0.0.1:8000/mcp/,http://127.0.0.1:8010/mcp/
MCP_AUTH_TOKENS=token-for-server-1,token-for-server-2
```

Tool names are namespaced as `{server_id}__{tool_name}`. The approval gate (`SENSITIVE_TOOLS`) always checks the unqualified name via `pool.original_name()`, so `srv2__breach_check` is gated exactly like `breach_check`.

## Multi-agent (A2A) pipeline

```
User <-> Orchestrator (agents/orchestrator.py, Gemini-driven, CLI)
              |  A2A calls (client/a2a_pool.py)
              |
              +--> Security Specialist (agents/security_specialist.py, :8100)
              |       MCP-backed — 6 tools as A2A skills
              |
              +--> Report-Writer Specialist (agents/report_writer_specialist.py, :8200)
                      Pure Gemini synthesis, no MCP dependency
```

**Run it** (4 terminals, in order):
```bash
python -m server.main
python -m agents.security_specialist
python -m agents.report_writer_specialist
python -m agents.orchestrator
```

## Resources & Prompts

- **Resource** `scan://history` — in-memory log of the last 200 tool invocations, most recent first.
- **Prompt** `generate_security_report(target, findings)` — turns raw findings into a structured report.

## Approval gate for sensitive tools

`breach_check` and `cve_lookup` are gated behind explicit user approval before running. The loop returns `{"status": "approval_needed", "pending": [...], "resume_state": {...}}` and waits for a `y/N` in the CLI or checkbox click in the dashboard.

## Auth on the transport

The MCP server requires a bearer token on every request (`MCP_AUTH_TOKEN`). **The server refuses to start if the token isn't set.** Clients send `Authorization: Bearer <token>`; a missing or wrong token gets `401 Unauthorized`.

## Running the tests

```bash
pytest tests/ -v
```

| Test file | What it tests | Needs API key? |
|-----------|--------------|---------------|
| `test_auth.py` | Missing/invalid/valid bearer token | No |
| `test_multi_server.py` | Tool merging, namespacing, routing across 2 servers | No |
| `test_memory_architecture.py` | Memory layer structure and import paths | No |
| `test_a2a_pipeline.py` | A2A specialist delegation, chaining, failure handling | Partial (failure test: No) |
| `test_e2e.py` | Full query → tool call → answer, per tool | Yes |

## What each tool does

| Tool | What it does | Data source |
|---|---|---|
| `password_strength` | Scores password entropy; flags short/simple/common | Local computation |
| `hash_password` / `verify_password_hash` | Hash or verify with MD5, SHA1, SHA256, or bcrypt | Local computation |
| `breach_check` ⚠️ | Checks if a password appeared in breach dumps | [HIBP Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) — k-anonymity, no key |
| `cve_lookup` ⚠️ | Looks up a CVE by ID or keyword | [NVD REST API v2](https://nvd.nist.gov/developers/vulnerabilities) |
| `log_analyzer` | Flags failed logins, port scans, SQLi patterns | Local regex, no network |

⚠️ = gated behind the approval gate (outbound calls).

### A note on `breach_check`

Uses HIBP's **k-anonymity** flow: only the first 5 hex chars of the SHA1 hash are sent to HIBP; comparison happens locally. The full password and hash are never transmitted. No `HIBP_API_KEY` is needed or used.

## Safe defaults on external calls

`breach_check` and `cve_lookup` both:
- **Validate input length** before making any call
- **Rate-limit** with an in-memory sliding-window limiter (`breach_check`: 15/60s; `cve_lookup`: 5/30s matching NVD's unauthenticated limit — bypassed when `NVD_API_KEY` is set)

## Error handling

Every tool wraps its logic in try/except at the FastMCP registration layer — no unhandled exception can crash the server. Invalid input returns a structured `{"error": "..."}` object. Obsidian and Cognee memory failures are caught and logged as warnings — they never crash the agent.
