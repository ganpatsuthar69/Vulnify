"""Protected administrative routes requiring explicit admin privileges."""

from fastapi import APIRouter, Depends, HTTPException, status
from vulnify.dependencies import require_admin
from vulnify.graph.user_repository import IUserRepository, get_user_repository
from vulnify.schemas import RoleUpdateRequest, UserResponse

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
