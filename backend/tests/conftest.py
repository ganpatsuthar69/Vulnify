"""Pytest configuration and fixtures for backend authentication tests."""

from collections.abc import AsyncIterator
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
import pytest

from vulnify.config import Settings, get_settings
from vulnify.graph.user_repository import InMemoryUserRepository, get_user_repository
from vulnify.main import create_app
from vulnify.rate_limiter import login_rate_limiter

TEST_SESSION_SECRET = "test_session_secret_that_is_at_least_32_chars_long!"


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
def app(test_settings: Settings, mock_user_repo: InMemoryUserRepository) -> FastAPI:
    test_app = create_app(settings=test_settings)
    test_app.dependency_overrides[get_settings] = lambda: test_settings
    test_app.dependency_overrides[get_user_repository] = lambda: mock_user_repo
    return test_app


@pytest.fixture(autouse=True)
def reset_state(mock_user_repo: InMemoryUserRepository) -> None:
    login_rate_limiter.reset()
    mock_user_repo.clear()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "vulnify"},
    ) as ac:
        yield ac
