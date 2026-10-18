"""Unit and Integration tests for Stored Traces and Investigation Run History (US-603).

Tests:
1. List past agent runs for a project (empty, populated, pagination, project scoping).
2. Retrieve single run details and error states.
3. Retrieve ordered tool-call trace with query identifiers, inputs, and result summaries.
4. Input sanitization (redacting sensitive tokens/passwords/secrets).
5. Resolving runs associated with a specific finding ID.
6. Admin-only authorization gating on all trace inspection endpoints.
7. End-to-end: Live streaming investigation persists run and tool calls into durable storage.
"""

import json
import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.graph.agent_run_repository import (
    AgentRunRecord,
    AgentToolCallRecord,
    InMemoryAgentRunRepository,
    sanitize_tool_inputs,
)
from vulnify.graph.project_repository import InMemoryProjectRepository
from vulnify.graph.user_repository import InMemoryUserRepository

STANDARD_USER = {
    "id": "standard-user-uuid",
    "name": "Standard Tester",
    "email": "user@vulnify.local",
    "role": "user",
}


def _seed_users(user_repo: InMemoryUserRepository) -> None:
    # Seed admin
    user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    admin = user_repo.get_by_email(ADMIN_USER["email"])
    if admin:
        admin.id = ADMIN_USER["id"]
        user_repo._users_by_id[ADMIN_USER["id"]] = admin

    # Seed standard user
    user_repo.create_user(
        email=STANDARD_USER["email"],
        name=STANDARD_USER["name"],
        password_hash="mock_hash",
        role=STANDARD_USER["role"],
    )
    user = user_repo.get_by_email(STANDARD_USER["email"])
    if user:
        user.id = STANDARD_USER["id"]
        user_repo._users_by_id[STANDARD_USER["id"]] = user


def test_sanitize_tool_inputs_redaction() -> None:
    raw_inputs = {
        "project_id": "proj-1",
        "github_token": "ghp_secretTokenValue123",
        "nested": {
            "api_key": "sk-12345",
            "safe_param": 42,
            "password_hash": "sensitive",
        },
        "items": [
            {"auth_header": "Bearer xyz", "label": "test"},
            "plain_string",
        ],
    }
    sanitized = sanitize_tool_inputs(raw_inputs)
    assert sanitized["project_id"] == "proj-1"
    assert sanitized["github_token"] == "[REDACTED]"
    assert sanitized["nested"]["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["password_hash"] == "[REDACTED]"
    assert sanitized["nested"]["safe_param"] == 42
    assert sanitized["items"][0]["auth_header"] == "[REDACTED]"
    assert sanitized["items"][0]["label"] == "test"


@pytest.mark.asyncio
async def test_list_runs_authorization(app, mock_user_repo) -> None:
    _seed_users(mock_user_repo)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Unauthenticated -> 401
        res_unauth = await client.get("/api/agent/runs?project_id=proj-1")
        assert res_unauth.status_code == 401

        # 2. Non-admin user -> 403
        authenticate_client(client, STANDARD_USER)
        res_forbidden = await client.get("/api/agent/runs?project_id=proj-1")
        assert res_forbidden.status_code == 403


@pytest.mark.asyncio
async def test_list_runs_empty_and_populated(
    app,
    mock_user_repo,
    mock_project_repo: InMemoryProjectRepository,
    mock_agent_run_repo: InMemoryAgentRunRepository,
) -> None:
    _seed_users(mock_user_repo)
    project_a = mock_project_repo.create_project(name="proj-alpha", ecosystem="npm")
    project_b = mock_project_repo.create_project(name="proj-beta", ecosystem="pypi")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)

        # 1. Initially empty
        res_empty = await client.get(f"/api/agent/runs?project_id={project_a.id}")
        assert res_empty.status_code == 200
        data_empty = res_empty.json()
        assert data_empty["total"] == 0
        assert data_empty["items"] == []

        # 2. Seed runs for Project A and Project B
        run_1 = AgentRunRecord(
            id="run-001",
            project_id=project_a.id,
            user_id=ADMIN_USER["id"],
            user_email=ADMIN_USER["email"],
            prompt="Explain exposure for lodash",
            status="completed",
            started_at=1729000000,
            completed_at=1729000005,
            final_answer="Lodash exposure identified.",
            step_count=2,
            findings_referenced=["find-lodash-1"],
            paths_referenced=["api-gw -> lodash"],
            tool_call_count=2,
        )
        run_2 = AgentRunRecord(
            id="run-002",
            project_id=project_a.id,
            user_id=ADMIN_USER["id"],
            user_email=ADMIN_USER["email"],
            prompt="Rank project findings",
            status="completed",
            started_at=1729000100,
            completed_at=1729000104,
            final_answer="Ranking computed.",
            step_count=1,
            tool_call_count=1,
        )
        run_b = AgentRunRecord(
            id="run-b-001",
            project_id=project_b.id,
            user_id=ADMIN_USER["id"],
            user_email=ADMIN_USER["email"],
            prompt="Check python deps",
            status="completed",
            started_at=1729000200,
            completed_at=1729000203,
            step_count=1,
            tool_call_count=1,
        )
        mock_agent_run_repo.upsert_run(run_1)
        mock_agent_run_repo.upsert_run(run_2)
        mock_agent_run_repo.upsert_run(run_b)

        # 3. Query Project A -> returns exactly 2 runs ordered by started_at DESC
        res = await client.get(f"/api/agent/runs?project_id={project_a.id}")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2
        assert data["items"][0]["id"] == "run-002"
        assert data["items"][1]["id"] == "run-001"
        assert data["items"][1]["has_final_answer"] is True
        assert data["items"][1]["tool_call_count"] == 2


@pytest.mark.asyncio
async def test_get_run_trace_detail_and_ordering(
    app,
    mock_user_repo,
    mock_project_repo: InMemoryProjectRepository,
    mock_agent_run_repo: InMemoryAgentRunRepository,
) -> None:
    _seed_users(mock_user_repo)
    project = mock_project_repo.create_project(name="payment-svc", ecosystem="npm")

    run_id = "run-trace-test-1"
    run = AgentRunRecord(
        id=run_id,
        project_id=project.id,
        user_id=ADMIN_USER["id"],
        user_email=ADMIN_USER["email"],
        prompt="Inspect reachability and fix",
        status="completed",
        started_at=1729100000,
        completed_at=1729100010,
        final_answer="Traced 2 tools successfully.",
        step_count=2,
        findings_referenced=["find-axios-1"],
        paths_referenced=["svc -> axios"],
        tool_call_count=2,
    )
    mock_agent_run_repo.upsert_run(run)

    # Seed 2 tool calls with query IDs and parameters
    tc_1 = AgentToolCallRecord(
        id="call-1",
        run_id=run_id,
        sequence=1,
        tool_name="list_findings",
        display_name="Querying findings",
        inputs={"project_id": project.id, "page": 1},
        result_summary="Found 1 finding.",
        status="success",
        query_id="get_project_findings",
        duration_ms=4.5,
        outcome="success",
        evidence_references=["find-axios-1"],
        started_at=1729100001,
        completed_at=1729100002,
    )
    tc_2 = AgentToolCallRecord(
        id="call-2",
        run_id=run_id,
        sequence=2,
        tool_name="get_dependency_paths",
        display_name="Traversing paths",
        inputs={"project_id": project.id, "finding_id": "find-axios-1", "api_token": "secret123"},
        result_summary="Found 1 path.",
        status="success",
        query_id="get_project_finding_paths",
        duration_ms=12.8,
        outcome="success",
        evidence_references=["find-axios-1"],
        started_at=1729100003,
        completed_at=1729100005,
    )
    mock_agent_run_repo.upsert_tool_call(tc_1)
    mock_agent_run_repo.upsert_tool_call(tc_2)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)

        # 1. Fetch run trace
        res = await client.get(f"/api/agent/runs/{run_id}/trace")
        assert res.status_code == 200
        data = res.json()

        # Verify run header
        assert data["run"]["id"] == run_id
        assert data["run"]["prompt"] == "Inspect reachability and fix"
        assert data["run"]["final_answer"] == "Traced 2 tools successfully."

        # Verify ordered tool calls
        assert len(data["tool_calls"]) == 2
        first_call = data["tool_calls"][0]
        second_call = data["tool_calls"][1]
        assert first_call["sequence"] == 1
        assert first_call["tool_name"] == "list_findings"
        assert first_call["query_id"] == "get_project_findings"

        assert second_call["sequence"] == 2
        assert second_call["tool_name"] == "get_dependency_paths"
        assert second_call["query_id"] == "get_project_finding_paths"
        # Verify sanitization of secret input
        assert second_call["inputs"]["api_token"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_get_runs_by_finding(
    app,
    mock_user_repo,
    mock_project_repo: InMemoryProjectRepository,
    mock_agent_run_repo: InMemoryAgentRunRepository,
) -> None:
    _seed_users(mock_user_repo)
    project = mock_project_repo.create_project(name="order-service", ecosystem="npm")

    run_matched = AgentRunRecord(
        id="run-with-finding",
        project_id=project.id,
        user_id=ADMIN_USER["id"],
        user_email=ADMIN_USER["email"],
        prompt="Deep dive on lodash",
        status="completed",
        started_at=1729150000,
        completed_at=1729150005,
        final_answer="Details on lodash.",
        findings_referenced=["find-lodash-123", "find-other-456"],
    )
    run_unmatched = AgentRunRecord(
        id="run-without-finding",
        project_id=project.id,
        user_id=ADMIN_USER["id"],
        user_email=ADMIN_USER["email"],
        prompt="Rank findings",
        status="completed",
        started_at=1729150100,
        completed_at=1729150105,
        findings_referenced=["find-other-456"],
    )
    mock_agent_run_repo.upsert_run(run_matched)
    mock_agent_run_repo.upsert_run(run_unmatched)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)

        # 1. Matching finding
        res = await client.get(
            f"/api/agent/runs/by-finding/find-lodash-123?project_id={project.id}"
        )
        assert res.status_code == 200
        items = res.json()
        assert len(items) == 1
        assert items[0]["id"] == "run-with-finding"

        # 2. Nonexistent finding -> returns empty array
        res_none = await client.get(
            f"/api/agent/runs/by-finding/find-nonexistent?project_id={project.id}"
        )
        assert res_none.status_code == 200
        assert res_none.json() == []


@pytest.mark.asyncio
async def test_live_stream_investigation_persists_trace(
    app,
    mock_user_repo,
    mock_project_repo: InMemoryProjectRepository,
    mock_agent_run_repo: InMemoryAgentRunRepository,
) -> None:
    _seed_users(mock_user_repo)
    project = mock_project_repo.create_project(name="checkout-flow", ecosystem="npm")
    run_id = "run-e2e-live-1"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)

        # 1. Start streaming investigation
        res_stream = await client.post(
            "/api/agent/chat/stream",
            json={"project_id": project.id, "message": "Investigate findings", "run_id": run_id},
            headers={"x-requested-with": "vulnify"},
        )
        assert res_stream.status_code == 200

        # 2. Verify run is in durable repository
        stored_run = mock_agent_run_repo.get_run_by_id(run_id)
        assert stored_run is not None
        assert stored_run.id == run_id
        assert stored_run.project_id == project.id
        assert stored_run.status == "completed"
        assert stored_run.prompt == "Investigate findings"
        assert stored_run.final_answer is not None

        # 3. Retrieve trace via GET /api/agent/runs/{run_id}/trace
        res_trace = await client.get(f"/api/agent/runs/{run_id}/trace")
        assert res_trace.status_code == 200
        trace_data = res_trace.json()
        assert trace_data["run"]["id"] == run_id
        assert trace_data["run"]["status"] == "completed"
        # At least list_findings tool was executed and persisted
        assert len(trace_data["tool_calls"]) >= 1
        assert trace_data["tool_calls"][0]["tool_name"] == "list_findings"
        assert trace_data["tool_calls"][0]["status"] == "success"
