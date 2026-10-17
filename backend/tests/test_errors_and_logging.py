"""Unit and integration tests for US-004: Consistent Errors and Structured Logging."""

import asyncio
import io
import json
import logging
from fastapi import APIRouter, FastAPI
from httpx import ASGITransport, AsyncClient
import pytest

from vulnify.config import Settings, get_settings
from vulnify.errors import AppException, create_error_response
from vulnify.graph.user_repository import InMemoryUserRepository, get_user_repository
from vulnify.logging import StructuredJsonFormatter, get_request_id, setup_logging
from vulnify.main import create_app

fault_router = APIRouter(prefix="/api/test-faults", tags=["test-faults"])


@fault_router.get("/expected-app-error")
async def trigger_expected_app_error() -> None:
    raise AppException(
        status_code=400,
        code="PROJECT_NOT_FOUND",
        message="The requested project was not found.",
    )


@fault_router.get("/unexpected-server-error")
async def trigger_unexpected_server_error() -> None:
    # Deliberate unhandled exception with sensitive internal context
    raise RuntimeError("Internal DB crashed with secret_token=super_secret_token_12345 at /var/secrets")


@pytest.fixture
def fault_app(test_settings: Settings, mock_user_repo: InMemoryUserRepository) -> FastAPI:
    """FastAPI test app configured with fault injection routes."""
    app = create_app(settings=test_settings)
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_user_repository] = lambda: mock_user_repo
    app.include_router(fault_router)
    return app


@pytest.fixture
async def fault_client(fault_app: FastAPI) -> AsyncClient:
    transport = ASGITransport(app=fault_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "vulnify"},
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_standardized_error_format_keys(fault_client: AsyncClient) -> None:
    """Expected application error returns exactly code, message, request_id with matching header."""
    res = await fault_client.get("/api/test-faults/expected-app-error")
    assert res.status_code == 400
    data = res.json()

    assert set(data.keys()) == {"code", "message", "request_id"}
    assert data["code"] == "PROJECT_NOT_FOUND"
    assert data["message"] == "The requested project was not found."
    assert isinstance(data["request_id"], str)
    assert len(data["request_id"]) > 0
    assert res.headers.get("X-Request-ID") == data["request_id"]


@pytest.mark.asyncio
async def test_validation_error_standardized_format(fault_client: AsyncClient) -> None:
    """Request validation failure (422) returns standardized error response without leaking sensitive inputs."""
    res = await fault_client.post(
        "/api/auth/register",
        json={"name": "Alice", "email": "alice@example.com", "password": "short"},
    )
    assert res.status_code == 422
    data = res.json()

    assert set(data.keys()) == {"code", "message", "request_id"}
    assert data["code"] == "VALIDATION_ERROR"
    assert "password" in data["message"].lower()
    # Ensure sensitive plaintext password input is never echoed in error message
    assert "short" not in data["message"]
    assert res.headers.get("X-Request-ID") == data["request_id"]


@pytest.mark.asyncio
async def test_authentication_error_standardized_format(fault_client: AsyncClient) -> None:
    """Unauthenticated access to protected route returns 401 with standardized error response."""
    res = await fault_client.get("/api/auth/me")
    assert res.status_code == 401
    data = res.json()

    assert set(data.keys()) == {"code", "message", "request_id"}
    assert data["code"] == "AUTHENTICATION_REQUIRED"
    assert data["message"] == "Authentication required."
    assert res.headers.get("X-Request-ID") == data["request_id"]


@pytest.mark.asyncio
async def test_missing_route_returns_standardized_404(fault_client: AsyncClient) -> None:
    """Accessing non-existent API route returns 404 with standardized error response."""
    res = await fault_client.get("/api/nonexistent-resource-endpoint")
    assert res.status_code == 404
    data = res.json()

    assert set(data.keys()) == {"code", "message", "request_id"}
    assert data["code"] == "NOT_FOUND"
    assert data["message"] == "The requested resource was not found."
    assert res.headers.get("X-Request-ID") == data["request_id"]


@pytest.mark.asyncio
async def test_unsupported_method_returns_standardized_405(fault_client: AsyncClient) -> None:
    """Using unsupported HTTP method returns 405 with standardized error response."""
    res = await fault_client.post("/api/health")
    assert res.status_code == 405
    data = res.json()

    assert set(data.keys()) == {"code", "message", "request_id"}
    assert data["code"] == "METHOD_NOT_ALLOWED"
    assert data["message"] == "Method not allowed for this endpoint."
    assert res.headers.get("X-Request-ID") == data["request_id"]


@pytest.mark.asyncio
async def test_unexpected_exception_masks_internal_details(fault_client: AsyncClient) -> None:
    """Unhandled server exceptions return generic message without exposing traces or secrets."""
    res = await fault_client.get("/api/test-faults/unexpected-server-error")
    assert res.status_code == 500
    data = res.json()

    assert set(data.keys()) == {"code", "message", "request_id"}
    assert data["code"] == "INTERNAL_SERVER_ERROR"
    assert data["message"] == "An unexpected error occurred."
    assert res.headers.get("X-Request-ID") == data["request_id"]

    # Verify internal details and secrets are not leaked to the client response
    assert "super_secret_token_12345" not in res.text
    assert "Traceback" not in res.text
    assert "/var/secrets" not in res.text


@pytest.mark.asyncio
async def test_valid_incoming_request_id_is_preserved(fault_client: AsyncClient) -> None:
    """A valid, safe incoming X-Request-ID header is preserved and returned."""
    trusted_id = "trusted-client-trace-987654"
    res = await fault_client.get(
        "/api/health",
        headers={"X-Request-ID": trusted_id},
    )
    assert res.status_code == 200
    assert res.headers.get("X-Request-ID") == trusted_id


@pytest.mark.asyncio
async def test_invalid_incoming_request_id_is_rejected_and_replaced(fault_client: AsyncClient) -> None:
    """Malicious or invalid incoming X-Request-ID headers are replaced with safe generated IDs."""
    malicious_ids = [
        "id_with_spaces in between",
        "id<script>alert(1)</script>",
        "id\r\nInjected-Header: evil",
        "a" * 100,  # exceeds 64 characters limit
    ]

    for bad_id in malicious_ids:
        res = await fault_client.get(
            "/api/health",
            headers={"X-Request-ID": bad_id},
        )
        assert res.status_code == 200
        assigned_id = res.headers.get("X-Request-ID")
        assert assigned_id != bad_id
        assert assigned_id is not None
        assert assigned_id.startswith("req-")
        assert len(assigned_id) <= 64


@pytest.mark.asyncio
async def test_concurrent_requests_isolate_request_ids(fault_client: AsyncClient) -> None:
    """Concurrent asynchronous requests maintain distinct request IDs without cross-contamination."""
    num_requests = 20

    async def run_req(index: int) -> tuple[str, str, str]:
        req_id = f"trace-concurrent-{index:04d}"
        res = await fault_client.get(
            "/api/health",
            headers={"X-Request-ID": req_id},
        )
        returned_id = res.headers.get("X-Request-ID", "")
        return str(index), req_id, returned_id

    results = await asyncio.gather(*(run_req(i) for i in range(num_requests)))

    seen_ids = set()
    for index_str, expected_id, actual_id in results:
        assert actual_id == expected_id, f"Mismatched ID for request index {index_str}"
        assert actual_id not in seen_ids, f"Duplicate request ID detected: {actual_id}"
        seen_ids.add(actual_id)


@pytest.mark.asyncio
async def test_structured_logging_records_contain_request_id_and_fields(fault_client: AsyncClient) -> None:
    """Structured JSON logs contain timestamp, level, request_id, method, path, and status."""
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setFormatter(StructuredJsonFormatter())

    vulnify_logger = logging.getLogger("vulnify")
    vulnify_logger.addHandler(handler)

    try:
        custom_id = "trace-log-test-4321"
        res = await fault_client.get(
            "/api/health",
            headers={"X-Request-ID": custom_id},
        )
        assert res.status_code == 200

        handler.flush()
        output = log_capture.getvalue()
        lines = [line.strip() for line in output.splitlines() if line.strip()]

        found_match = False
        for line in lines:
            try:
                record = json.loads(line)
                if record.get("request_id") == custom_id:
                    found_match = True
                    assert record.get("method") == "GET"
                    assert record.get("path") == "/api/health"
                    assert record.get("status_code") == 200
                    assert "timestamp" in record
                    assert "level" in record
            except json.JSONDecodeError:
                continue

        assert found_match, f"Expected log record with request_id={custom_id} in logs:\n{output}"
    finally:
        vulnify_logger.removeHandler(handler)


@pytest.mark.asyncio
async def test_openapi_docs_preserved(fault_client: AsyncClient) -> None:
    """Non-API routes like /openapi.json preserve standard schema output."""
    res = await fault_client.get("/openapi.json")
    assert res.status_code == 200
    schema = res.json()
    assert "openapi" in schema
    assert "paths" in schema
