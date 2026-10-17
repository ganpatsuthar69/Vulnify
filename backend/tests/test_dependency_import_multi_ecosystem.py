"""API endpoint integration tests for multi-ecosystem dependency import and capabilities."""

import json
from httpx import AsyncClient
import pytest

from tests.conftest import ADMIN_USER, authenticate_client
from tests.test_cargo_parser import SAMPLE_CARGO_LOCK
from tests.test_golang_parser import SAMPLE_GO_MOD, SAMPLE_GO_SUM
from tests.test_python_parser import SAMPLE_POETRY_LOCK, SAMPLE_REQUIREMENTS_TXT, SAMPLE_UV_LOCK
from vulnify.graph.dependency_repository import InMemoryDependencyRepository
from vulnify.graph.project_repository import InMemoryProjectRepository
from vulnify.graph.user_repository import InMemoryUserRepository


@pytest.fixture(autouse=True)
def seed_admin(
    mock_user_repo: InMemoryUserRepository,
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


@pytest.mark.asyncio
async def test_get_ecosystem_capabilities_endpoint(client: AsyncClient) -> None:
    authenticate_client(client)
    res = await client.get("/api/projects/ecosystem-capabilities")
    assert res.status_code == 200
    data = res.json()
    assert "supported_ecosystems" in data
    assert "capabilities" in data
    eco_ids = data["supported_ecosystems"]
    assert "npm" in eco_ids
    assert "PyPI" in eco_ids
    assert "Cargo" in eco_ids
    assert "Go" in eco_ids

    caps = {c["id"]: c for c in data["capabilities"]}
    assert "Cargo" in caps
    assert caps["Cargo"]["osv_ecosystem"] == "crates.io"
    assert "Go" in caps
    assert caps["Go"]["osv_ecosystem"] == "Go"


@pytest.mark.asyncio
async def test_python_poetry_and_uv_import(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    py_proj = mock_project_repo.create_project(name="Data Analytics API", ecosystem="PyPI")

    # 1. Import poetry.lock
    res1 = await client.post(
        f"/api/projects/{py_proj.id}/dependencies/import",
        json={
            "service_name": "worker",
            "filename": "poetry.lock",
            "content": SAMPLE_POETRY_LOCK,
        },
    )
    assert res1.status_code == 200
    d1 = res1.json()
    assert d1["service_name"] == "worker"
    assert d1["packages_parsed"] == 3
    assert d1["fidelity"] == "exact_lockfile"
    assert d1["ecosystem"] == "PyPI"

    # 2. Import uv.lock
    res2 = await client.post(
        f"/api/projects/{py_proj.id}/dependencies/import",
        json={
            "service_name": "web",
            "filename": "uv.lock",
            "content": SAMPLE_UV_LOCK,
        },
    )
    assert res2.status_code == 200
    d2 = res2.json()
    assert d2["packages_parsed"] == 3
    assert d2["fidelity"] == "exact_lockfile"


@pytest.mark.asyncio
async def test_python_requirements_txt_with_honest_fidelity(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    py_proj = mock_project_repo.create_project(name="Legacy Script", ecosystem="PyPI")

    res = await client.post(
        f"/api/projects/{py_proj.id}/dependencies/import",
        json={
            "service_name": "script-svc",
            "filename": "requirements.txt",
            "content": SAMPLE_REQUIREMENTS_TXT,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["packages_parsed"] == 2
    assert data["fidelity"] == "manifest_declared"
    assert len(data["warnings"]) > 0


@pytest.mark.asyncio
async def test_cargo_lockfile_import(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    cargo_proj = mock_project_repo.create_project(name="High Perf Engine", ecosystem="Cargo")

    res = await client.post(
        f"/api/projects/{cargo_proj.id}/dependencies/import",
        json={
            "service_name": "engine",
            "filename": "Cargo.lock",
            "content": SAMPLE_CARGO_LOCK,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["packages_parsed"] == 3
    assert data["fidelity"] == "exact_lockfile"
    assert data["ecosystem"] == "Cargo"


@pytest.mark.asyncio
async def test_golang_mod_and_sum_paired_import(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    go_proj = mock_project_repo.create_project(name="Auth Gateway", ecosystem="Go")

    # Import with paired go.sum
    res = await client.post(
        f"/api/projects/{go_proj.id}/dependencies/import",
        json={
            "service_name": "gateway",
            "filename": "go.mod",
            "content": SAMPLE_GO_MOD,
            "secondary_filename": "go.sum",
            "secondary_content": SAMPLE_GO_SUM,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["packages_parsed"] == 4
    assert data["fidelity"] == "checksum_verified"
    assert data["ecosystem"] == "Go"


@pytest.mark.asyncio
async def test_mismatched_ecosystem_format_rejected(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    authenticate_client(client)
    cargo_proj = mock_project_repo.create_project(name="Rust Service", ecosystem="Cargo")

    # Uploading requirements.txt to a Cargo project
    res = await client.post(
        f"/api/projects/{cargo_proj.id}/dependencies/import",
        json={
            "service_name": "svc",
            "filename": "requirements.txt",
            "content": "requests==2.31.0",
        },
    )
    assert res.status_code == 422
    assert "unsupported lockfile format" in res.json()["message"].lower()
    assert "cargo" in res.json()["message"].lower()
