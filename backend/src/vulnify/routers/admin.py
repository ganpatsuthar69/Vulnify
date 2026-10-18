"""Protected administrative routes requiring explicit admin privileges."""

from fastapi import APIRouter, Depends, HTTPException, status
from vulnify.dependencies import require_admin
from vulnify.graph.user_repository import IUserRepository, get_user_repository
from vulnify.schemas import (
    GitHubConfigResponse,
    GitHubConfigUpdateRequest,
    GitHubConfigValidateRequest,
    GitHubValidationResultResponse,
    RoleUpdateRequest,
    UserResponse,
)
from vulnify.services.github_service import GitHubService, get_github_service

router = APIRouter(
    prefix="/api/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


@router.get("/status", summary="Admin status check")
async def admin_status(current_admin: UserResponse = Depends(require_admin)) -> dict[str, str]:
    """Protected admin health check."""
    return {"status": "ok", "admin": current_admin.email, "role": current_admin.role}


@router.post("/promote", response_model=UserResponse, summary="Promote or update user role")
async def promote_user(
    body: RoleUpdateRequest,
    current_admin: UserResponse = Depends(require_admin),
    repo: IUserRepository = Depends(get_user_repository),
) -> UserResponse:
    """Deliberate admin-only endpoint to promote or alter user role."""
    updated = repo.update_role(body.email, body.role)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    return UserResponse(
        id=updated.id,
        email=updated.email,
        name=updated.name,
        role=updated.role,
    )


# =====================================================================
# US-506: GitHub Integration Admin Configuration Endpoints
# =====================================================================


@router.get(
    "/github-config",
    response_model=GitHubConfigResponse,
    summary="Get GitHub integration configuration (US-506)",
)
async def get_admin_github_config(
    project_id: str | None = None,
    current_admin: UserResponse = Depends(require_admin),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubConfigResponse:
    """Retrieve current non-sensitive GitHub integration configuration."""
    return github_service.get_config(project_id)


@router.post(
    "/github-config",
    response_model=GitHubConfigResponse,
    summary="Update and validate GitHub integration configuration (US-506)",
)
async def update_admin_github_config(
    body: GitHubConfigUpdateRequest,
    current_admin: UserResponse = Depends(require_admin),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubConfigResponse:
    """Update GitHub target repository and credentials, with permission validation against GitHub API."""
    return await github_service.update_config(
        owner=body.owner,
        repo=body.repo,
        token=body.token,
        api_base_url=body.api_base_url,
        project_id=body.project_id,
        validate_before_save=body.validate_before_save,
        current_user=current_admin,
    )


@router.post(
    "/github-config/validate",
    response_model=GitHubValidationResultResponse,
    summary="Validate GitHub target repository access and permissions (US-506)",
)
async def validate_admin_github_config(
    body: GitHubConfigValidateRequest,
    current_admin: UserResponse = Depends(require_admin),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubValidationResultResponse:
    """Test connectivity and repository permissions against GitHub REST API without mutating configuration."""
    return await github_service.validate_target_repo_access(
        owner=body.owner,
        repo=body.repo,
        token=body.token,
        project_id=body.project_id,
    )

