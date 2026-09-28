import pytest

from memory.agent_memory import AgentMemoryService, ExecutionStore, FileArtifactStore
from memory.chat_memory import ChatMemoryService, ObsidianVault


class FakeWorkingMemory:
    def __init__(self):
        self.events = {}
        self.values = {}

    async def append_event(self, scope, identifier, event, max_events=100):
        key = (scope, identifier)
        self.events.setdefault(key, []).append(event)
        self.events[key] = self.events[key][-max_events:]

    async def get_events(self, scope, identifier):
        return self.events.get((scope, identifier), [])

    async def put_json(self, scope, identifier, value):
        self.values[(scope, identifier)] = value


class FakeCognee:
    def __init__(self):
        self.memories = []

    async def remember(self, text, dataset):
        self.memories.append((dataset, text))

    async def recall(self, query, dataset):
        return [text for remembered_dataset, text in self.memories if remembered_dataset == dataset and query.lower() in text.lower()]


@pytest.mark.asyncio
async def test_chat_memory_keeps_context_in_redis_and_turns_in_obsidian(tmp_path):
    working = FakeWorkingMemory()
    service = ChatMemoryService(working, ObsidianVault(tmp_path / "vault"), context_limit=2)
    path = await service.add_turn("conversation/1", "user", "Find Log4Shell", trace_id="trace-1")
    await service.add_turn("conversation/1", "assistant", "I will look it up.")

    assert "Find Log4Shell" in path.read_text(encoding="utf-8")
    assert [turn["role"] for turn in await service.context("conversation/1")] == ["user", "assistant"]


@pytest.mark.asyncio
async def test_agent_memory_splits_working_semantic_records_and_artifacts(tmp_path):
    working, semantic = FakeWorkingMemory(), FakeCognee()
    executions = ExecutionStore(tmp_path / "executions.sqlite3")
    service = AgentMemoryService(working, semantic, executions, FileArtifactStore(tmp_path / "artifacts"))

    run_id = await service.start("trace-agent-1", "security-agent", "Analyze an authentication log")
    artifact = await service.record_tool_result(run_id, "security-agent", "log_analyzer", {"findings": ["brute force"]}, status="ok")
    service.finish(run_id, "completed")

    assert artifact["uri"].startswith("file:")
    assert len(executions.timeline("trace-agent-1")) == 3
    assert await service.recall("security-agent", "authentication")
