"""Health check endpoints (US-904).

Exposes:
- GET /api/health: Combined liveness and readiness check. Returns 200 OK when ready, 503 Service Unavailable when FalkorDB is down.
- GET /api/health/liveness: Lightweight process liveness probe (always 200 OK if process is responding).
- GET /api/health/readiness: Database readiness probe (200 OK when FalkorDB is ready, 503 Service Unavailable when down).
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, Response, status

from vulnify.graph.client import GraphClient, get_graph_client
from vulnify.schemas import DatabaseHealthMetrics, HealthResponse, QueryMetrics

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("", response_model=HealthResponse)
async def health_check(
    response: Response,
    probe: str | None = Query(None, description="Optional probe filter ('liveness' or 'readiness')"),
    client: GraphClient = Depends(get_graph_client),
) -> HealthResponse:
    """Public health status check.
    
    Returns 200 OK when healthy and ready to serve traffic.
    Returns 503 Service Unavailable when FalkorDB database is unreachable or unhealthy.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    query_metrics = QueryMetrics(**client.get_query_metrics())

    if probe == "liveness":
        return HealthResponse(
            status="healthy",
            liveness="ok",
            readiness="ready",
            database=DatabaseHealthMetrics(status="connected"),
            query_metrics=query_metrics,
            timestamp=now_iso,
        )

    db_health_raw = client.check_health()
    db_metrics = DatabaseHealthMetrics(**db_health_raw)
    is_ready = db_metrics.status == "connected"

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status="healthy" if is_ready else "unhealthy",
        liveness="ok",
        readiness="ready" if is_ready else "not_ready",
        database=db_metrics,
        query_metrics=query_metrics,
        timestamp=now_iso,
    )


@router.get("/liveness")
async def liveness_check() -> dict[str, str]:
    """Dedicated liveness check for Kubernetes / container orchestrators."""
    return {"status": "healthy", "liveness": "ok"}


@router.get("/readiness", response_model=HealthResponse)
async def readiness_check(
    response: Response,
    client: GraphClient = Depends(get_graph_client),
) -> HealthResponse:
    """Dedicated readiness check verifying FalkorDB connectivity."""
    return await health_check(response=response, probe="readiness", client=client)
