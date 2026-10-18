"""Comprehensive tests for US-904: Detailed Database Health Metrics and Readiness Probes.

Covers:
1. API liveness (/api/health/liveness and /api/health?probe=liveness)
2. Database readiness with live FalkorDB (200 OK, real metrics: latency, memory, uptime, version)
3. Database failure handling (503 Service Unavailable, safe status, safe error category)
4. Query timeout handling (503 Service Unavailable, TIMEOUT error category)
5. Query metrics telemetry (counts, success/fail tracking, average latency, thread-safety)
6. Separation of application liveness and database readiness
7. Safe error categorization and zero secret leakage in health responses
8. Recovery after transient failure
9. Concurrent health requests isolation
10. Non-mutating probe verification
"""

import asyncio
from datetime import datetime
import socket
from typing import Any
from unittest.mock import MagicMock, patch
from fastapi import FastAPI, status
from httpx import ASGITransport, AsyncClient
import pytest

from vulnify.config import Settings, get_settings
from vulnify.graph.client import GraphClient, get_graph_client
from vulnify.main import create_app
from vulnify.schemas import HealthResponse


@pytest.fixture
def health_app(test_settings: Settings) -> FastAPI:
    """Create FastAPI application configured for health check tests."""
    app = create_app(settings=test_settings)
    app.dependency_overrides[get_settings] = lambda: test_settings
    return app


@pytest.fixture
async def health_client(health_app: FastAPI) -> AsyncClient:
    """AsyncClient for testing health routes."""
    transport = ASGITransport(app=health_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Requested-With": "vulnify"},
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_api_liveness_dedicated_endpoint(health_client: AsyncClient) -> None:
    """Liveness probe returns 200 OK with process status."""
    res = await health_client.get("/api/health/liveness")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["status"] == "healthy"
    assert data["liveness"] == "ok"


@pytest.mark.asyncio
async def test_api_liveness_probe_query_parameter(health_client: AsyncClient) -> None:
    """GET /api/health?probe=liveness returns 200 OK regardless of database state."""
    res = await health_client.get("/api/health?probe=liveness")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["status"] == "healthy"
    assert data["liveness"] == "ok"
    assert "timestamp" in data
    assert "query_metrics" in data


@pytest.mark.asyncio
async def test_database_readiness_healthy(health_client: AsyncClient) -> None:
    """Readiness probe returns 200 OK when FalkorDB is reachable and responsive."""
    res = await health_client.get("/api/health/readiness")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["status"] == "healthy"
    assert data["liveness"] == "ok"
    assert data["readiness"] == "ready"

    db = data["database"]
    assert db["status"] == "connected"
    assert db["latency_ms"] is not None
    assert db["latency_ms"] >= 0.0
    assert db["error"] is None
    assert db["graph_name"] == "vulnify"
    # Verify real database signals from FalkorDB/Redis INFO
    if db["server_version"] is not None:
        assert isinstance(db["server_version"], str)
    if db["uptime_seconds"] is not None:
        assert db["uptime_seconds"] >= 0
    if db["used_memory_human"] is not None:
        assert "M" in db["used_memory_human"] or "K" in db["used_memory_human"] or "G" in db["used_memory_human"] or "B" in db["used_memory_human"]


@pytest.mark.asyncio
async def test_combined_health_endpoint_healthy(health_client: AsyncClient) -> None:
    """GET /api/health returns 200 OK with full system telemetry when DB is healthy."""
    res = await health_client.get("/api/health")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    # Validate against Pydantic schema
    validated = HealthResponse(**data)
    assert validated.status == "healthy"
    assert validated.readiness == "ready"
    assert validated.database.status == "connected"


@pytest.mark.asyncio
async def test_database_unreachable_returns_503(health_app: FastAPI, health_client: AsyncClient) -> None:
    """When FalkorDB is unreachable (connection refused), readiness returns 503 with safe category."""
    mock_client = MagicMock(spec=GraphClient)
    mock_client.check_health.return_value = {
        "status": "disconnected",
        "latency_ms": None,
        "uptime_seconds": None,
        "used_memory_human": None,
        "connected_clients": None,
        "server_version": None,
        "graph_name": "vulnify",
        "error": "CONNECTION_REFUSED",
    }
    mock_client.get_query_metrics.return_value = {
        "total_queries": 4,
        "successful_queries": 2,
        "failed_queries": 2,
        "timeout_queries": 0,
        "avg_query_latency_ms": 2.5,
    }

    health_app.dependency_overrides[get_graph_client] = lambda: mock_client
    try:
        res = await health_client.get("/api/health")
        assert res.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = res.json()
        assert data["status"] == "unhealthy"
        assert data["liveness"] == "ok"  # Process is alive
        assert data["readiness"] == "not_ready"  # DB is not ready
        assert data["database"]["status"] == "disconnected"
        assert data["database"]["error"] == "CONNECTION_REFUSED"
        # Missing metrics are None (unavailable), not zero
        assert data["database"]["latency_ms"] is None
        assert data["database"]["uptime_seconds"] is None
        assert data["database"]["used_memory_human"] is None
    finally:
        health_app.dependency_overrides.pop(get_graph_client, None)


@pytest.mark.asyncio
async def test_database_timeout_returns_503(health_app: FastAPI, health_client: AsyncClient) -> None:
    """When FalkorDB query times out, readiness returns 503 with TIMEOUT error category."""
    mock_client = MagicMock(spec=GraphClient)
    mock_client.check_health.return_value = {
        "status": "disconnected",
        "latency_ms": None,
        "uptime_seconds": None,
        "used_memory_human": None,
        "connected_clients": None,
        "server_version": None,
        "graph_name": "vulnify",
        "error": "TIMEOUT",
    }
    mock_client.get_query_metrics.return_value = {
        "total_queries": 1,
        "successful_queries": 0,
        "failed_queries": 1,
        "timeout_queries": 1,
        "avg_query_latency_ms": None,
    }

    health_app.dependency_overrides[get_graph_client] = lambda: mock_client
    try:
        res = await health_client.get("/api/health/readiness")
        assert res.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = res.json()
        assert data["status"] == "unhealthy"
        assert data["readiness"] == "not_ready"
        assert data["database"]["error"] == "TIMEOUT"
    finally:
        health_app.dependency_overrides.pop(get_graph_client, None)


@pytest.mark.asyncio
async def test_secret_redaction_in_health_response(health_app: FastAPI, health_client: AsyncClient) -> None:
    """Raw driver exceptions with passwords/connection strings are never leaked in response."""
    test_secret = "super_secret_redis_password_xyz987"
    raw_error_message = f"ConnectionError to redis://default:{test_secret}@127.0.0.1:6379/vulnify failed"

    # Verify check_health sanitization on GraphClient directly
    fake_settings = Settings(
        SESSION_SECRET="dummy_session_secret_at_least_32_characters_long",
        FALKORDB_PASSWORD=test_secret,
    )
    client = GraphClient(fake_settings)

    with patch.object(client, "get_graph", side_effect=ConnectionRefusedError(raw_error_message)):
        health_dict = client.check_health()
        assert health_dict["status"] == "disconnected"
        assert health_dict["error"] == "CONNECTION_REFUSED"
        # Secret string must NOT be anywhere in error string
        assert test_secret not in str(health_dict["error"])
        assert "password" not in str(health_dict["error"]).lower()


def test_query_metrics_telemetry_and_isolation(test_settings: Settings) -> None:
    """Query telemetry increments on application queries, records latency, tracks failures."""
    client = GraphClient(test_settings)
    client.reset_metrics()

    initial = client.get_query_metrics()
    assert initial["total_queries"] == 0
    assert initial["successful_queries"] == 0
    assert initial["failed_queries"] == 0
    assert initial["timeout_queries"] == 0
    assert initial["avg_query_latency_ms"] is None  # Unmeasured is None, not 0.0

    # 1. Health check probe does not pollute application query counts
    health_dict = client.check_health()
    assert health_dict["status"] == "connected"
    after_health = client.get_query_metrics()
    assert after_health["total_queries"] == 0

    # 2. Application query increments successful_queries and avg latency
    graph = client.get_graph()
    res = graph.query("RETURN 100 AS num")
    assert res.result_set[0][0] == 100

    after_query = client.get_query_metrics()
    assert after_query["total_queries"] == 1
    assert after_query["successful_queries"] == 1
    assert after_query["failed_queries"] == 0
    assert after_query["avg_query_latency_ms"] is not None
    assert after_query["avg_query_latency_ms"] >= 0.0

    # 3. Failing query increments failed_queries
    with pytest.raises(Exception):
        graph.query("SYNTAX ERROR IN CYPHER QUERY")

    after_fail = client.get_query_metrics()
    assert after_fail["total_queries"] == 2
    assert after_fail["successful_queries"] == 1
    assert after_fail["failed_queries"] == 1


@pytest.mark.asyncio
async def test_recovery_after_transient_failure(health_app: FastAPI, health_client: AsyncClient) -> None:
    """System transitions from unhealthy (503) to healthy (200) once database recovers."""
    mock_client = MagicMock(spec=GraphClient)
    # First call: DB is down
    down_health = {
        "status": "disconnected",
        "latency_ms": None,
        "uptime_seconds": None,
        "used_memory_human": None,
        "connected_clients": None,
        "server_version": None,
        "graph_name": "vulnify",
        "error": "CONNECTION_REFUSED",
    }
    # Second call: DB recovered
    up_health = {
        "status": "connected",
        "latency_ms": 1.25,
        "uptime_seconds": 1200,
        "used_memory_human": "12.0M",
        "connected_clients": 2,
        "server_version": "8.10.2",
        "graph_name": "vulnify",
        "error": None,
    }
    mock_client.check_health.side_effect = [down_health, up_health]
    mock_client.get_query_metrics.return_value = {
        "total_queries": 0,
        "successful_queries": 0,
        "failed_queries": 0,
        "timeout_queries": 0,
        "avg_query_latency_ms": None,
    }

    health_app.dependency_overrides[get_graph_client] = lambda: mock_client
    try:
        # Request 1: down
        res1 = await health_client.get("/api/health")
        assert res1.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert res1.json()["readiness"] == "not_ready"

        # Request 2: recovered
        res2 = await health_client.get("/api/health")
        assert res2.status_code == status.HTTP_200_OK
        assert res2.json()["readiness"] == "ready"
        assert res2.json()["database"]["status"] == "connected"
    finally:
        health_app.dependency_overrides.pop(get_graph_client, None)


@pytest.mark.asyncio
async def test_concurrent_health_requests_stability(health_client: AsyncClient) -> None:
    """Concurrent health checks execute reliably without data races."""
    num_requests = 10
    tasks = [health_client.get("/api/health") for _ in range(num_requests)]
    responses = await asyncio.gather(*tasks)

    for res in responses:
        assert res.status_code == status.HTTP_200_OK
        data = res.json()
        assert data["status"] == "healthy"
        assert data["database"]["status"] == "connected"
