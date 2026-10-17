"""API routes for on-demand vulnerability evaluation and version matching."""

from fastapi import APIRouter, Depends, HTTPException, status

from vulnify.dependencies import require_auth
from vulnify.schemas import UserResponse, VersionEvaluationRequest, VersionMatchResultResponse
from vulnify.version_matching.service import (
    VersionMatchingService,
    get_version_matching_service,
)

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.post(
    "/evaluate",
    response_model=VersionMatchResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a single package version against an OSV advisory",
)
async def evaluate_version_advisory(
    payload: VersionEvaluationRequest,
    current_user: UserResponse = Depends(require_auth),
    matching_service: VersionMatchingService = Depends(get_version_matching_service),
) -> VersionMatchResultResponse:
    """Evaluate whether an imported package version is affected by an OSV advisory payload.
    
    Adheres strictly to the package's ecosystem version comparison semantics and OSV range events.
    """
    try:
        res = matching_service.evaluate_single(
            package_name=payload.package_name,
            package_version=payload.package_version,
            ecosystem=payload.ecosystem,
            advisory_payload=payload.advisory,
        )
        return VersionMatchResultResponse(
            package_name=res.package_name,
            package_version=res.package_version,
            ecosystem=res.ecosystem,
            advisory_id=res.advisory_id,
            status=res.status.value,
            reason_code=res.reason_code.value,
            reason=res.reason,
            matched_range=res.matched_range,
            fixed_version=res.fixed_version,
            comparator=res.comparator,
            evaluated_at=res.evaluated_at,
            fingerprint=res.fingerprint,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to evaluate version: {str(exc)}",
        ) from exc
