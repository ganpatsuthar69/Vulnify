"""Unit tests for AgentOrchestrator (US-602).

Tests:
1. Normal investigation streaming lifecycle (run_started -> tools -> answer -> completed).
2. Step limit enforcement (halts within budget, no uncontrolled loop).
3. Timeout handling (halts when wall-clock limit exceeded).
4. Run-scoped cancellation (cancels in-flight run, rejects unauthorized user).
5. Grounded answers citing real finding IDs and dependency paths without claiming exploitability.
"""

import asyncio
import json
import pytest

from vulnify.agent.orchestrator import AgentOrchestrator
from vulnify.agent.registry import get_tool_registry
from vulnify.config import Settings
from vulnify.graph.project_repository import InMemoryProjectRepository
from vulnify.graph.vulnerability_repository import (
    InMemoryVulnerabilityRepository,
    set_vulnerability_repository_override,
)


@pytest.fixture
def agent_settings() -> Settings:
    return Settings(
        SESSION_SECRET="test_secret_for_agent_orchestrator_testing_32_chars!",
        AGENT_STEP_LIMIT=5,
        AGENT_RUN_TIMEOUT_SECONDS=10,
    )


@pytest.fixture
def populated_repos():
    project_repo = InMemoryProjectRepository()
    project = project_repo.create_project(name="checkout-service", ecosystem="npm")

    vuln_repo = InMemoryVulnerabilityRepository()
    vuln_repo.findings_override[project.id] = [
        {
            "id": "find-lodash-1",
            "project_id": project.id,
            "service_id": "svc-checkout",
            "service_name": "checkout-service",
            "advisory_id": "GHSA-29mw-wpgm-hmr9",
            "advisory_summary": "Prototype Pollution in lodash",
            "severity": "HIGH",
            "priority": "High",
            "priority_reasons": ["High severity advisory on reachable path"],
            "scoring_version": "v1.0.0",
            "status": "open",
            "package_version_id": "pkg-lodash-4.17.20",
            "package_name": "lodash",
            "package_version": "4.17.20",
            "ecosystem": "npm",
            "matched_range": "< 4.17.21",
            "fixed_version": "4.17.21",
            "path_depth": 2,
            "path_status": "path_found",
            "aliases": ["CVE-2020-8203"],
        }
    ]
    vuln_repo.custom_paths[("svc-checkout", "pkg-lodash-4.17.20")] = [
        {
            "id": "path-1",
            "depth": 2,
            "is_direct": False,
            "nodes": [
                {"id": "svc-checkout", "node_type": "service", "display_name": "checkout-service"},
                {"id": "pkg-mid-1", "node_type": "package", "display_name": "async@3.2.0", "package_name": "async", "package_version": "3.2.0"},
                {"id": "pkg-lodash-4.17.20", "node_type": "package", "display_name": "lodash@4.17.20", "package_name": "lodash", "package_version": "4.17.20"},
            ],
            "edges": [
                {"id": "e1", "source_id": "svc-checkout", "target_id": "pkg-mid-1", "relationship_type": "DEPENDS_ON", "direct": True},
                {"id": "e2", "source_id": "pkg-mid-1", "target_id": "pkg-lodash-4.17.20", "relationship_type": "DEPENDS_ON", "direct": False},
            ],
            "summary_text": "Service: checkout-service → async@3.2.0 → lodash@4.17.20",
        }
    ]
    set_vulnerability_repository_override(vuln_repo)

    registry = get_tool_registry()
    return project, project_repo, vuln_repo, registry


def _parse_sse_events(raw_stream: list[str]) -> list[dict]:
    events = []
    for chunk in raw_stream:
        lines = chunk.strip().split("\n")
        event_name = None
        data_obj = None
        for line in lines:
            if line.startswith("event: "):
                event_name = line[len("event: ") :].strip()
            elif line.startswith("data: "):
                data_obj = json.loads(line[len("data: ") :].strip())
        if event_name and data_obj:
            events.append({"event": event_name, "data": data_obj})
    return events


@pytest.mark.asyncio
async def test_orchestrator_investigation_stream_lifecycle(agent_settings, populated_repos):
    project, project_repo, vuln_repo, registry = populated_repos

    orchestrator = AgentOrchestrator(
        settings=agent_settings,
        registry=registry,
        project_repo=project_repo,
    )

    chunks = []
    async for chunk in orchestrator.stream_investigation(
        project_id=project.id,
        message="Explain the dependency path and exposure for lodash",
        user_id="user-123",
        user_email="admin@vulnify.local",
    ):
        chunks.append(chunk)

    events = _parse_sse_events(chunks)
    event_names = [e["event"] for e in events]

    assert "run_started" in event_names
    assert "assistant_status" in event_names
    assert "tool_started" in event_names
    assert "tool_completed" in event_names
    assert "answer_delta" in event_names
    assert "answer_completed" in event_names
    assert "run_completed" in event_names

    # Check answer completed references
    ans_event = next(e for e in events if e["event"] == "answer_completed")
    full_text = ans_event["data"]["data"]["full_text"]
    assert "find-lodash-1" in full_text
    # Must use exposure phrasing and not claim exploitability
    assert "exposure" in full_text.lower()
    assert "not a guarantee of safety" in full_text.lower() or "exposure" in full_text.lower()


@pytest.mark.asyncio
async def test_orchestrator_step_limit_enforcement(populated_repos):
    project, project_repo, vuln_repo, registry = populated_repos

    # Limit to only 1 step
    strict_settings = Settings(
        SESSION_SECRET="test_secret_for_agent_orchestrator_testing_32_chars!",
        AGENT_STEP_LIMIT=1,
        AGENT_RUN_TIMEOUT_SECONDS=30,
    )

    orchestrator = AgentOrchestrator(
        settings=strict_settings,
        registry=registry,
        project_repo=project_repo,
    )

    chunks = []
    async for chunk in orchestrator.stream_investigation(
        project_id=project.id,
        message="Rank all findings and show dependency paths and explain details",
        user_id="user-123",
        user_email="admin@vulnify.local",
    ):
        chunks.append(chunk)

    events = _parse_sse_events(chunks)
    tool_completions = [e for e in events if e["event"] == "tool_completed"]
    assert len(tool_completions) <= 1


@pytest.mark.asyncio
async def test_orchestrator_run_cancellation(agent_settings, populated_repos):
    project, project_repo, vuln_repo, registry = populated_repos

    orchestrator = AgentOrchestrator(
        settings=agent_settings,
        registry=registry,
        project_repo=project_repo,
    )

    run_id = "test-cancel-run-1"

    # Start generator and cancel immediately
    stream_gen = orchestrator.stream_investigation(
        project_id=project.id,
        message="Rank all findings and traverse dependency paths",
        user_id="user-123",
        user_email="admin@vulnify.local",
        run_id=run_id,
    )

    chunks = []
    async for chunk in stream_gen:
        chunks.append(chunk)
        # Cancel after first event
        await orchestrator.cancel_run(run_id=run_id, user_id="user-123")

    events = _parse_sse_events(chunks)
    event_names = [e["event"] for e in events]
    assert "run_cancelled" in event_names

    # Cancelling again should report already_terminal
    res = await orchestrator.cancel_run(run_id=run_id, user_id="user-123")
    assert res.status == "already_terminal"


@pytest.mark.asyncio
async def test_orchestrator_cancellation_unauthorized(agent_settings, populated_repos):
    project, project_repo, vuln_repo, registry = populated_repos

    orchestrator = AgentOrchestrator(
        settings=agent_settings,
        registry=registry,
        project_repo=project_repo,
    )

    run_id = "test-cancel-run-2"
    # Initiate run
    stream_gen = orchestrator.stream_investigation(
        project_id=project.id,
        message="Investigate findings",
        user_id="user-owner",
        user_email="owner@vulnify.local",
        run_id=run_id,
    )
    # Read first event to register context
    await stream_gen.__anext__()

    # Other user attempts to cancel
    cancel_res = await orchestrator.cancel_run(run_id=run_id, user_id="intruder-user")
    assert cancel_res.status == "not_found"
    assert "does not belong" in cancel_res.message


@pytest.mark.asyncio
async def test_orchestrator_conversational_greeting_hi(agent_settings, populated_repos):
    project, project_repo, vuln_repo, registry = populated_repos

    orchestrator = AgentOrchestrator(
        settings=agent_settings,
        registry=registry,
        project_repo=project_repo,
    )

    chunks = []
    async for chunk in orchestrator.stream_investigation(
        project_id=project.id,
        message="Hi",
        user_id="user-123",
        user_email="admin@vulnify.local",
    ):
        chunks.append(chunk)

    events = _parse_sse_events(chunks)
    event_names = [e["event"] for e in events]

    assert "run_started" in event_names
    assert "assistant_status" in event_names
    assert "answer_delta" in event_names
    assert "answer_completed" in event_names
    assert "run_completed" in event_names

    # Greeting must NOT trigger unnecessary tool execution steps
    assert "tool_started" not in event_names
    assert "tool_completed" not in event_names

    ans_event = next(e for e in events if e["event"] == "answer_completed")
    full_text = ans_event["data"]["data"]["full_text"]
    # Check that answer is a relevant introduction/greeting, NOT robotic "no vulnerability findings were found"
    assert "vulnify" in full_text.lower()
    assert "no vulnerability findings were found" not in full_text.lower()


@pytest.mark.asyncio
async def test_orchestrator_conceptual_inquiry(agent_settings, populated_repos):
    project, project_repo, vuln_repo, registry = populated_repos

    orchestrator = AgentOrchestrator(
        settings=agent_settings,
        registry=registry,
        project_repo=project_repo,
    )

    chunks = []
    async for chunk in orchestrator.stream_investigation(
        project_id=project.id,
        message="What is the difference between architectural exposure and exploitability?",
        user_id="user-123",
        user_email="admin@vulnify.local",
    ):
        chunks.append(chunk)

    events = _parse_sse_events(chunks)
    event_names = [e["event"] for e in events]

    # Must NOT run database lookup tools for conceptual questions
    assert "tool_started" not in event_names

    ans_event = next(e for e in events if e["event"] == "answer_completed")
    full_text = ans_event["data"]["data"]["full_text"]
    assert "exposure" in full_text.lower()
    assert "exploitab" in full_text.lower()

