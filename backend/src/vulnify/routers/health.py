"""Health check endpoint."""

from fastapi import APIRouter
from vulnify.schemas import HealthResponse

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Public health status check."""
    return HealthResponse(status="healthy")
