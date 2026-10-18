"""API endpoint tests for Agent Discovery and Execution Router (US-601)."""

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.graph.user_repository import InMemoryUserRepository


def _seed_user(user_repo: InMemoryUserRepository) -> None:
    user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    user = user_repo.get_by_email(ADMIN_USER["email"])
    if user:
        user.id = ADMIN_USER["id"]
        user_repo._users_by_id[ADMIN_USER["id"]] = user


@pytest.mark.asyncio
async def test_list_tools_unauthenticated(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/agent/tools")
        assert res.status_code == 401


@pytest.mark.asyncio
async def test_list_tools_authenticated(app, mock_user_repo) -> None:
    _seed_user(mock_user_repo)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)
        res = await client.get("/api/agent/tools")
        assert res.status_code == 200

        data = res.json()
        assert data["total"] == 7
        tool_names = [t["name"] for t in data["tools"]]
        assert "list_findings" in tool_names
        assert "record_decision" in tool_names
        assert "open_fix_issue" in tool_names


@pytest.mark.asyncio
async def test_get_tool_definition(app, mock_user_repo) -> None:
    _seed_user(mock_user_repo)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)

        # Existing tool
        res = await client.get("/api/agent/tools/get_dependency_paths")
        assert res.status_code == 200
        data = res.json()
        assert data["name"] == "get_dependency_paths"
        assert data["classification"] == "read_only"
        assert data["query_id"] == "get_project_finding_paths"

        # Nonexistent tool
        res_404 = await client.get("/api/agent/tools/nonexistent_tool")
        assert res_404.status_code == 404


@pytest.mark.asyncio
async def test_execute_tool_csrf_enforcement(app, mock_user_repo) -> None:
    _seed_user(mock_user_repo)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)

        # POST without X-Requested-With header fails with 403 CSRF error
        res = await client.post(
            "/api/agent/tools/list_findings/execute",
            json={"project_id": "proj-1"},
        )
        assert res.status_code == 403
        assert "X-Requested-With" in res.json().get("message", "")


@pytest.mark.asyncio
async def test_execute_tool_authenticated_with_csrf(app, mock_user_repo, mock_vuln_repo) -> None:
    _seed_user(mock_user_repo)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)
        headers = {"x-requested-with": "vulnify"}

        # 1. Execute read-only tool
        res = await client.post(
            "/api/agent/tools/list_findings/execute",
            json={"project_id": "proj-empty"},
            headers=headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["tool_name"] == "list_findings"
        assert data["status"] == "success"
        assert data["trace"]["query_id"] == "get_project_findings"

        # 2. Execute gated write tool without confirmation -> returns rejected status
        res_write = await client.post(
            "/api/agent/tools/record_decision/execute",
            json={
                "project_id": "proj-empty",
                "finding_id": "find-1",
                "status": "affected",
                "confirmed": False,
            },
            headers=headers,
        )
        assert res_write.status_code == 200
        write_data = res_write.json()
        assert write_data["status"] == "rejected"
        assert write_data["trace"]["outcome"] == "rejected"
        assert "explicit human approval is required" in write_data["error_message"]
