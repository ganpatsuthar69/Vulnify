"""Pytest configuration and fixtures for backend authentication tests."""

from collections.abc import AsyncIterator
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
import pytest

from vulnify.config import Settings, get_settings
from vulnify.dependencies import COOKIE_SESSION_NAME
from vulnify.graph.advisory_repository import InMemoryAdvisoryRepository, get_advisory_repository
from vulnify.graph.dependency_repository import InMemoryDependencyRepository, get_dependency_repository
from vulnify.graph.job_repository import InMemoryIngestionJobRepository, get_job_repository
from vulnify.graph.project_repository import InMemoryProjectRepository, get_project_repository
from vulnify.graph.user_repository import InMemoryUserRepository, get_user_repository
from vulnify.graph.vulnerability_repository import (
    InMemoryVulnerabilityRepository,
    get_vulnerability_repository,
)
from vulnify.main import create_app
from vulnify.rate_limiter import login_rate_limiter
from vulnify.security import create_session_jwt

TEST_SESSION_SECRET = "test_session_secret_that_is_at_least_32_chars_long!"

ADMIN_USER = {
    "id": "admin-user-uuid",
    "name": "Admin Tester",
    "email": "admin@vulnify.local",
    "role": "admin",
}


def authenticate_client(client: AsyncClient, user_data: dict[str, str] = ADMIN_USER) -> None:
    """Helper to set authenticated session cookie on test client."""
    token = create_session_jwt(
        user_id=user_data["id"],
        email=user_data["email"],
        role=user_data["role"],
        secret=TEST_SESSION_SECRET,
        ttl_minutes=480,
    )
    client.cookies.set(COOKIE_SESSION_NAME, token)


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        FALKORDB_HOST="localhost",
        FALKORDB_PORT=6379,
        FALKORDB_GRAPH="vulnify",
        SESSION_SECRET=TEST_SESSION_SECRET,
        SESSION_TTL_MINUTES=480,
        COOKIE_SECURE=False,
        ALLOWED_ORIGINS="http://localhost:5173,http://test",
    )


@pytest.fixture
def mock_user_repo() -> InMemoryUserRepository:
    return InMemoryUserRepository()


@pytest.fixture
def mock_project_repo() -> InMemoryProjectRepository:
    return InMemoryProjectRepository()


@pytest.fixture
def mock_dep_repo() -> InMemoryDependencyRepository:
    return InMemoryDependencyRepository()


@pytest.fixture
def mock_advisory_repo() -> InMemoryAdvisoryRepository:
    return InMemoryAdvisoryRepository()


@pytest.fixture
def mock_vuln_repo() -> InMemoryVulnerabilityRepository:
    return InMemoryVulnerabilityRepository()


@pytest.fixture
def mock_job_repo() -> InMemoryIngestionJobRepository:
    return InMemoryIngestionJobRepository()


@pytest.fixture
def app(
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_dep_repo: InMemoryDependencyRepository,
    mock_advisory_repo: InMemoryAdvisoryRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> FastAPI:
    test_app = create_app(settings=test_settings)
    test_app.dependency_overrides[get_settings] = lambda: test_settings
    test_app.dependency_overrides[get_user_repository] = lambda: mock_user_repo
    test_app.dependency_overrides[get_project_repository] = lambda: mock_project_repo
    test_app.dependency_overrides[get_dependency_repository] = lambda: mock_dep_repo
    test_app.dependency_overrides[get_advisory_repository] = lambda: mock_advisory_repo
    test_app.dependency_overrides[get_vulnerability_repository] = lambda: mock_vuln_repo
    test_app.dependency_overrides[get_job_repository] = lambda: mock_job_repo
    return test_app


@pytest.fixture(autouse=True)
def reset_state(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_dep_repo: InMemoryDependencyRepository,
    mock_advisory_repo: InMemoryAdvisoryRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    login_rate_limiter.reset()
    mock_user_repo.clear()
    mock_project_repo.clear()
    mock_dep_repo.clear()
    mock_advisory_repo.clear()
    mock_vuln_repo.package_advisories.clear()
    mock_vuln_repo.affects_edges.clear()
    mock_vuln_repo.vulnerabilities_data.clear()
    mock_vuln_repo.services.clear()
    mock_vuln_repo.findings_override.clear()
    mock_job_repo._jobs.clear()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "vulnify"},
    ) as ac:
        yield ac
