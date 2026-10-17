"""API endpoint integration tests for US-102: Lockfile upload and dependency import."""

import json
from httpx import AsyncClient
import pytest

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.graph.dependency_repository import InMemoryDependencyRepository
from vulnify.graph.project_repository import InMemoryProjectRepository
from vulnify.graph.user_repository import InMemoryUserRepository

VALID_LOCKFILE = {
    "name": "web-service",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "dependencies": {
                "express": "^4.18.2",
            },
        },
        "node_modules/express": {
            "version": "4.18.2",
            "dependencies": {
                "accepts": "~1.3.8",
            },
        },
        "node_modules/accepts": {
            "version": "1.3.8",
        },
    },
}


@pytest.fixture(autouse=True)
def seed_admin_and_project(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    mock_user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    user = mock_user_repo.get_by_email(ADMIN_USER["email"])
    if user:
        user.id = ADMIN_USER["id"]
        mock_user_repo._users_by_id[ADMIN_USER["id"]] = user

    # Seed npm project
    mock_project_repo.create_project(
        name="Payment Gateway",
        ecosystem="npm",
        description="Payment API",
    )


@pytest.mark.asyncio
async def test_authenticated_json_upload_succeeds(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.get_by_normalized_name("payment gateway")
    assert project is not None

    res = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={
            "service_name": "payment-api",
            "filename": "package-lock.json",
            "content": json.dumps(VALID_LOCKFILE),
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["project_id"] == project.id
    assert data["service_name"] == "payment-api"
    assert data["filename"] == "package-lock.json"
    assert "sha256_hash" in data and len(data["sha256_hash"]) == 64
    assert data["packages_parsed"] == 2
    assert data["packages_created"] == 2
    assert data["packages_reused"] == 0
    assert data["edges_created"] == 2  # 1 service -> express, 1 express -> accepts
    assert data["edges_reused"] == 0
    assert data["status"] == "completed"
    assert "imported_at" in data


@pytest.mark.asyncio
async def test_authenticated_multipart_upload_succeeds(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.get_by_normalized_name("payment gateway")
    assert project is not None

    boundary = "----TestBoundary12345"
    content_str = json.dumps(VALID_LOCKFILE)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="service_name"\r\n\r\n'
        f"payment-api\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="package-lock.json"\r\n'
        f"Content-Type: application/json\r\n\r\n"
        f"{content_str}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    res = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["packages_parsed"] == 2
    assert data["service_name"] == "payment-api"


@pytest.mark.asyncio
async def test_unauthenticated_upload_rejected(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    project = mock_project_repo.get_by_normalized_name("payment gateway")
    assert project is not None

    res = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={
            "service_name": "payment-api",
            "filename": "package-lock.json",
            "content": json.dumps(VALID_LOCKFILE),
        },
    )
    assert res.status_code == 401
    assert res.json()["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.asyncio
async def test_nonexistent_project_rejected(client: AsyncClient) -> None:
    authenticate_client(client)
    res = await client.post(
        "/api/projects/non-existent-uuid/dependencies/import",
        json={
            "service_name": "payment-api",
            "filename": "package-lock.json",
            "content": json.dumps(VALID_LOCKFILE),
        },
    )
    assert res.status_code == 404
    assert res.json()["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_missing_or_invalid_service_name_rejected(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.get_by_normalized_name("payment gateway")
    assert project is not None

    # Missing service name
    res1 = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={"content": json.dumps(VALID_LOCKFILE)},
    )
    assert res1.status_code == 422

    # Whitespace only
    res2 = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={"service_name": "   ", "content": json.dumps(VALID_LOCKFILE)},
    )
    assert res2.status_code == 422

    # Illegal characters
    res3 = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={"service_name": "service with spaces; rm -rf", "content": json.dumps(VALID_LOCKFILE)},
    )
    assert res3.status_code == 422


@pytest.mark.asyncio
async def test_missing_or_empty_lockfile_rejected(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.get_by_normalized_name("payment gateway")
    assert project is not None

    # Empty content
    res = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={"service_name": "payment-api", "content": ""},
    )
    assert res.status_code == 422
    assert "empty" in res.json().get("message", "").lower()


@pytest.mark.asyncio
async def test_unsupported_ecosystem_or_format_rejected(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)

    # 1. Project with PyPI ecosystem rejects npm lockfile
    pypi_proj = mock_project_repo.create_project(name="Python Service", ecosystem="PyPI")
    res1 = await client.post(
        f"/api/projects/{pypi_proj.id}/dependencies/import",
        json={
            "service_name": "py-api",
            "filename": "package-lock.json",
            "content": json.dumps(VALID_LOCKFILE),
        },
    )
    assert res1.status_code == 422
    assert "not currently supported" in res1.json().get("message", "").lower()

    # 2. npm project rejects unsupported file extension (e.g. poetry.lock)
    npm_proj = mock_project_repo.get_by_normalized_name("payment gateway")
    assert npm_proj is not None
    res2 = await client.post(
        f"/api/projects/{npm_proj.id}/dependencies/import",
        json={
            "service_name": "payment-api",
            "filename": "poetry.lock",
            "content": "[[package]]\nname = 'requests'",
        },
    )
    assert res2.status_code == 422
    assert "unsupported lockfile format" in res2.json().get("message", "").lower()


@pytest.mark.asyncio
async def test_oversized_file_rejected(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.get_by_normalized_name("payment gateway")
    assert project is not None

    # Simulate header exceeding 10MB limit
    res1 = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        headers={"Content-Length": str(15 * 1024 * 1024), "Content-Type": "application/json"},
        content=b"{}",
    )
    assert res1.status_code == 413
    assert "exceeds" in res1.json().get("message", "").lower()


@pytest.mark.asyncio
async def test_idempotent_reimport_summary(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.get_by_normalized_name("payment gateway")
    assert project is not None

    payload = {
        "service_name": "payment-api",
        "filename": "package-lock.json",
        "content": json.dumps(VALID_LOCKFILE),
    }

    # First import
    res1 = await client.post(f"/api/projects/{project.id}/dependencies/import", json=payload)
    assert res1.status_code == 200
    d1 = res1.json()
    assert d1["packages_created"] == 2
    assert d1["packages_reused"] == 0
    assert d1["edges_created"] == 2
    assert d1["edges_reused"] == 0

    # Second import of exact same file and service
    res2 = await client.post(f"/api/projects/{project.id}/dependencies/import", json=payload)
    assert res2.status_code == 200
    d2 = res2.json()
    assert d2["packages_parsed"] == 2
    assert d2["packages_created"] == 0
    assert d2["packages_reused"] == 2
    assert d2["edges_created"] == 0
    assert d2["edges_reused"] == 2


@pytest.mark.asyncio
async def test_database_error_does_not_leak_internal_details(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
    mock_dep_repo: InMemoryDependencyRepository,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.get_by_normalized_name("payment gateway")
    assert project is not None

    def buggy_import(*args, **kwargs):
        raise RuntimeError("FalkorDB SyntaxError at line 14: Cypher internal parse failure")

    mock_dep_repo.import_dependencies = buggy_import

    res = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={
            "service_name": "payment-api",
            "filename": "package-lock.json",
            "content": json.dumps(VALID_LOCKFILE),
        },
    )
    assert res.status_code == 500
    data = res.json()
    assert data["code"] == "INTERNAL_SERVER_ERROR"
    assert "FalkorDB" not in data["message"]
    assert "SyntaxError" not in data["message"]
    assert "Cypher" not in data["message"]
