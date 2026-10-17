"""Unit and integration tests for US-101: Project creation, listing, retrieval, and validation."""

from httpx import ASGITransport, AsyncClient
import pytest

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository

VALID_PROJECT = {
    "name": "Payment Service",
    "ecosystem": "npm",
    "description": "Payment application dependencies",
}


@pytest.fixture(autouse=True)
def seed_admin_user(mock_user_repo: InMemoryUserRepository) -> None:
    """Ensure authenticated admin exists in repository."""
    mock_user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    # Ensure ID matches
    user = mock_user_repo.get_by_email(ADMIN_USER["email"])
    if user:
        user.id = ADMIN_USER["id"]
        mock_user_repo._users_by_id[ADMIN_USER["id"]] = user


# 1. An authenticated admin can create a valid project
@pytest.mark.asyncio
async def test_create_valid_project(client: AsyncClient) -> None:
    authenticate_client(client)
    res = await client.post("/api/projects", json=VALID_PROJECT)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Payment Service"
    assert data["ecosystem"] == "npm"
    assert data["description"] == "Payment application dependencies"
    assert "id" in data and len(data["id"]) > 0
    assert "created_at" in data and isinstance(data["created_at"], int)


# 2. A project is persisted and can be retrieved later
@pytest.mark.asyncio
async def test_project_persisted_and_retrieved(client: AsyncClient) -> None:
    authenticate_client(client)
    res = await client.post("/api/projects", json=VALID_PROJECT)
    assert res.status_code == 201
    created_id = res.json()["id"]

    get_res = await client.get(f"/api/projects/{created_id}")
    assert get_res.status_code == 200
    retrieved = get_res.json()
    assert retrieved["id"] == created_id
    assert retrieved["name"] == "Payment Service"
    assert retrieved["ecosystem"] == "npm"
    assert retrieved["description"] == "Payment application dependencies"


# 3. Listing projects returns the correct project records
@pytest.mark.asyncio
async def test_list_projects(client: AsyncClient) -> None:
    authenticate_client(client)
    p1 = {"name": "Auth Gateway", "ecosystem": "npm", "description": "Auth service"}
    p2 = {"name": "Analytics Engine", "ecosystem": "PyPI", "description": "Data pipelines"}

    await client.post("/api/projects", json=p1)
    await client.post("/api/projects", json=p2)

    list_res = await client.get("/api/projects")
    assert list_res.status_code == 200
    projects = list_res.json()
    assert len(projects) == 2
    names = [p["name"] for p in projects]
    assert "Auth Gateway" in names
    assert "Analytics Engine" in names


# 4. Listing an empty database returns an empty array
@pytest.mark.asyncio
async def test_list_empty_database_returns_empty_array(client: AsyncClient) -> None:
    authenticate_client(client)
    list_res = await client.get("/api/projects")
    assert list_res.status_code == 200
    assert list_res.json() == []


# 5. Missing or whitespace-only project names are rejected
@pytest.mark.asyncio
async def test_reject_missing_or_whitespace_project_names(client: AsyncClient) -> None:
    authenticate_client(client)

    # Missing name
    res1 = await client.post("/api/projects", json={"ecosystem": "npm"})
    assert res1.status_code == 422

    # Empty string
    res2 = await client.post("/api/projects", json={"name": "", "ecosystem": "npm"})
    assert res2.status_code == 422

    # Whitespace only
    res3 = await client.post("/api/projects", json={"name": "    ", "ecosystem": "npm"})
    assert res3.status_code == 422
    err3 = res3.json()
    assert "empty or whitespace" in (err3.get("message") or "")


# 6. Unsupported ecosystems are rejected
@pytest.mark.asyncio
async def test_reject_unsupported_ecosystem(client: AsyncClient) -> None:
    authenticate_client(client)
    res = await client.post(
        "/api/projects",
        json={"name": "Go Microservice", "ecosystem": "unsupported_eco"},
    )
    assert res.status_code == 422
    data = res.json()
    assert "Unsupported ecosystem" in (data.get("message") or "")


# 7. Duplicate project names are rejected according to the chosen normalization policy
@pytest.mark.asyncio
async def test_reject_duplicate_project_names_case_insensitive(client: AsyncClient) -> None:
    authenticate_client(client)
    res1 = await client.post(
        "/api/projects",
        json={"name": "Billing Service", "ecosystem": "npm"},
    )
    assert res1.status_code == 201

    # Exact duplicate
    res2 = await client.post(
        "/api/projects",
        json={"name": "Billing Service", "ecosystem": "npm"},
    )
    assert res2.status_code == 409
    data2 = res2.json()
    assert data2["code"] == "CONFLICT"
    assert "already exists" in data2["message"]

    # Case-insensitive duplicate with whitespace variations
    res3 = await client.post(
        "/api/projects",
        json={"name": "  billing service  ", "ecosystem": "PyPI"},
    )
    assert res3.status_code == 409
    data3 = res3.json()
    assert data3["code"] == "CONFLICT"
    assert "already exists" in data3["message"]


# 8. Optional descriptions work correctly
@pytest.mark.asyncio
async def test_optional_description(client: AsyncClient) -> None:
    authenticate_client(client)

    # Omitted description
    res1 = await client.post("/api/projects", json={"name": "Project No Desc", "ecosystem": "npm"})
    assert res1.status_code == 201
    assert res1.json()["description"] is None

    # Empty string description -> normalized to None
    res2 = await client.post(
        "/api/projects",
        json={"name": "Project Empty Desc", "ecosystem": "npm", "description": "   "},
    )
    assert res2.status_code == 201
    assert res2.json()["description"] is None

    # Provided description
    res3 = await client.post(
        "/api/projects",
        json={"name": "Project Full Desc", "ecosystem": "npm", "description": "A detailed description."},
    )
    assert res3.status_code == 201
    assert res3.json()["description"] == "A detailed description."


# 9. Invalid request bodies return appropriate validation errors
@pytest.mark.asyncio
async def test_invalid_request_body_returns_validation_error(client: AsyncClient) -> None:
    authenticate_client(client)

    # Empty body
    res1 = await client.post("/api/projects", json={})
    assert res1.status_code == 422
    assert res1.json()["code"] == "VALIDATION_ERROR"

    # Non-json payload
    res2 = await client.post(
        "/api/projects",
        content="not-json",
        headers={"Content-Type": "application/json"},
    )
    assert res2.status_code == 422

    # Name too long (> 100 chars)
    res3 = await client.post(
        "/api/projects",
        json={"name": "x" * 101, "ecosystem": "npm"},
    )
    assert res3.status_code == 422

    # Description too long (> 500 chars)
    res4 = await client.post(
        "/api/projects",
        json={"name": "Valid Name", "ecosystem": "npm", "description": "x" * 501},
    )
    assert res4.status_code == 422


# 10. Unauthenticated requests are rejected
@pytest.mark.asyncio
async def test_unauthenticated_requests_are_rejected(client: AsyncClient) -> None:
    # No auth cookie
    res_list = await client.get("/api/projects")
    assert res_list.status_code == 401
    assert res_list.json()["code"] == "AUTHENTICATION_REQUIRED"

    res_create = await client.post("/api/projects", json=VALID_PROJECT)
    assert res_create.status_code == 401
    assert res_create.json()["code"] == "AUTHENTICATION_REQUIRED"

    res_get = await client.get("/api/projects/some-id")
    assert res_get.status_code == 401
    assert res_get.json()["code"] == "AUTHENTICATION_REQUIRED"


# 11. Database errors do not expose internal details
@pytest.mark.asyncio
async def test_database_errors_do_not_expose_internal_details(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)

    # Simulate database explosion with internal Cypher/driver details
    def buggy_create(*args, **kwargs):
        raise RuntimeError("FalkorDB SyntaxError at line 4: internal connection pool reset")

    mock_project_repo.create_project = buggy_create

    res = await client.post("/api/projects", json=VALID_PROJECT)
    assert res.status_code == 500
    data = res.json()
    assert data["code"] == "INTERNAL_SERVER_ERROR"
    # Never expose internal query or driver details
    assert "FalkorDB" not in data["message"]
    assert "SyntaxError" not in data["message"]
    assert "internal" not in data["message"]


# 12. Query parameters and unknown endpoints are safely handled
@pytest.mark.asyncio
async def test_query_parameters_and_get_by_id_safe(client: AsyncClient) -> None:
    authenticate_client(client)
    # Non-existent ID returns 404
    res_404 = await client.get("/api/projects/non-existent-uuid")
    assert res_404.status_code == 404
    assert res_404.json()["code"] == "NOT_FOUND"

    # Supported ecosystems metadata endpoint
    eco_res = await client.get("/api/projects/ecosystems")
    assert eco_res.status_code == 200
    ecosystems = eco_res.json()["supported_ecosystems"]
    assert "npm" in ecosystems
    assert "PyPI" in ecosystems
