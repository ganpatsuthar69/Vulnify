"""FastAPI dependencies for authentication, role-based access control, and user context."""

from fastapi import Depends, HTTPException, Request, status
import jwt

from vulnify.config import Settings, get_settings
from vulnify.graph.project_repository import (
    IProjectRepository,
    ProjectRecord,
    get_project_repository,
)
from vulnify.graph.user_repository import IUserRepository, get_user_repository
from vulnify.schemas import UserResponse
from vulnify.security import decode_session_jwt

COOKIE_SESSION_NAME = "vulnify_session"


async def require_auth(
    request: Request,
    settings: Settings = Depends(get_settings),
    repo: IUserRepository = Depends(get_user_repository),
) -> UserResponse:
    """Validate user session cookie and return the authenticated user.

    Fails closed with 401 Unauthorized if the cookie is missing, invalid, or expired.
    """
    token = request.cookies.get(COOKIE_SESSION_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    try:
        payload = decode_session_jwt(token, settings.SESSION_SECRET)
    except (jwt.PyJWTError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    user_id = payload.get("sub")
    email = payload.get("email")
    role = payload.get("role")

    if not user_id or not email or not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    # Fetch fresh user record from repository to guarantee user still exists
    user_record = repo.get_by_id(user_id)
    if not user_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    return UserResponse(
        id=user_record.id,
        email=user_record.email,
        name=user_record.name,
        role=user_record.role,  # fresh role from database
    )


async def require_admin(
    current_user: UserResponse = Depends(require_auth),
) -> UserResponse:
    """Validate that the authenticated user possesses the admin role.

    Returns 403 Forbidden if the user is authenticated but not an administrator.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required.",
        )
    return current_user


async def get_valid_project(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    repo: IProjectRepository = Depends(get_project_repository),
) -> ProjectRecord:
    """Validate that a project exists by ID and verify user authorization."""
    clean_id = project_id.strip()
    project = repo.get_by_id(clean_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID '{clean_id}' not found.",
        )

    # Multi-project data isolation & authorization:
    # Admins can access all projects.
    # Regular users can only access projects they created (or unowned demo projects).
    if current_user.role != "admin":
        if project.created_by is not None and str(project.created_by) != str(current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access to this project is forbidden.",
            )

    return project
