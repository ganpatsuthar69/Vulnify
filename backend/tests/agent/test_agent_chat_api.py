"""Integration tests for Agent Interactive Chat & Streaming Router (US-602).

Tests:
1. POST /api/agent/chat/stream unauthenticated -> 401 Unauthorized.
2. POST /api/agent/chat/stream non-admin user -> 403 Forbidden.
3. POST /api/agent/chat/stream missing CSRF header -> 403 Forbidden.
4. POST /api/agent/chat/stream missing/invalid project -> 404 Not Found.
5. POST /api/agent/chat/stream empty message -> 422 Unprocessable Entity.
6. POST /api/agent/chat/stream valid request -> 200 OK text/event-stream with SSE events.
7. POST /api/agent/runs/{run_id}/cancel admin authorization and cancellation response.
8. GET /api/agent/runs/{run_id}/status retrieval.
"""

import json
import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import ADMIN_USER, authenticate_client
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


@pytest.mark.asyncio
async def test_chat_stream_unauthenticated(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/agent/chat/stream",
            json={"project_id": "proj-1", "message": "Investigate findings"},
            headers={"x-requested-with": "vulnify"},
        )
        assert res.status_code == 401


@pytest.mark.asyncio
async def test_chat_stream_member_forbidden(app, mock_user_repo) -> None:
    _seed_users(mock_user_repo)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, STANDARD_USER)
        res = await client.post(
            "/api/agent/chat/stream",
            json={"project_id": "proj-1", "message": "Investigate findings"},
            headers={"x-requested-with": "vulnify"},
        )
        assert res.status_code == 403
        data = res.json()
        assert "Only signed-in administrators" in data.get("detail", data.get("message", ""))


@pytest.mark.asyncio
async def test_chat_stream_csrf_missing(app, mock_user_repo) -> None:
    _seed_users(mock_user_repo)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)
        res = await client.post(
            "/api/agent/chat/stream",
            json={"project_id": "proj-1", "message": "Investigate findings"},
        )
        assert res.status_code == 403
        data = res.json()
        assert "X-Requested-With" in data.get("message", "")


@pytest.mark.asyncio
async def test_chat_stream_project_not_found(app, mock_user_repo) -> None:
    _seed_users(mock_user_repo)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)
        res = await client.post(
            "/api/agent/chat/stream",
            json={"project_id": "nonexistent-project-id", "message": "Investigate findings"},
            headers={"x-requested-with": "vulnify"},
        )
        assert res.status_code == 404
        data = res.json()
        assert "not found" in data.get("detail", data.get("message", "")).lower()


@pytest.mark.asyncio
async def test_chat_stream_empty_message(app, mock_user_repo, mock_project_repo: InMemoryProjectRepository) -> None:
    _seed_users(mock_user_repo)
    project = mock_project_repo.create_project(name="test-repo", ecosystem="npm")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)
        res = await client.post(
            "/api/agent/chat/stream",
            json={"project_id": project.id, "message": "   "},
            headers={"x-requested-with": "vulnify"},
        )
        assert res.status_code == 422


@pytest.mark.asyncio
async def test_chat_stream_success(app, mock_user_repo, mock_project_repo: InMemoryProjectRepository) -> None:
    _seed_users(mock_user_repo)
    project = mock_project_repo.create_project(name="payment-gateway", ecosystem="npm")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)
        res = await client.post(
            "/api/agent/chat/stream",
            json={"project_id": project.id, "message": "What is the exposure in payment-gateway?"},
            headers={"x-requested-with": "vulnify"},
        )
        assert res.status_code == 200
        assert "text/event-stream" in res.headers["content-type"]

        # Parse SSE lines
        text = res.text
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        event_names = [line.replace("event: ", "") for line in lines if line.startswith("event: ")]

        assert "run_started" in event_names
        assert "run_completed" in event_names


@pytest.mark.asyncio
async def test_cancel_agent_run(app, mock_user_repo) -> None:
    _seed_users(mock_user_repo)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Non-admin cannot cancel
        authenticate_client(client, STANDARD_USER)
        res_forbidden = await client.post(
            "/api/agent/runs/fake-run-id/cancel",
            headers={"x-requested-with": "vulnify"},
        )
        assert res_forbidden.status_code == 403

        # 2. Admin can call cancel
        authenticate_client(client, ADMIN_USER)
        res_admin = await client.post(
            "/api/agent/runs/fake-run-id/cancel",
            headers={"x-requested-with": "vulnify"},
        )
        assert res_admin.status_code == 200
        data = res_admin.json()
        assert data["run_id"] == "fake-run-id"
        assert data["status"] == "not_found"


@pytest.mark.asyncio
async def test_get_agent_run_status(app, mock_user_repo, mock_project_repo: InMemoryProjectRepository) -> None:
    _seed_users(mock_user_repo)
    project = mock_project_repo.create_project(name="auth-service", ecosystem="npm")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        authenticate_client(client, ADMIN_USER)

        # 1. Nonexistent run
        res_404 = await client.get("/api/agent/runs/nonexistent-run/status")
        assert res_404.status_code == 404

        # 2. Start a run with a specific run_id
        run_id = "test-status-run-1"
        res_stream = await client.post(
            "/api/agent/chat/stream",
            json={"project_id": project.id, "message": "Check dependencies", "run_id": run_id},
            headers={"x-requested-with": "vulnify"},
        )
        assert res_stream.status_code == 200

        # 3. Retrieve status
        res_status = await client.get(f"/api/agent/runs/{run_id}/status")
        assert res_status.status_code == 200
        data = res_status.json()
        assert data["run_id"] == run_id
        assert data["project_id"] == project.id
        assert data["status"] == "completed"
