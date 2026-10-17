"""Authentication endpoints: registration, login, profile, and logout."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from vulnify.config import Settings, get_settings
from vulnify.dependencies import COOKIE_SESSION_NAME, require_auth
from vulnify.graph.user_repository import (
    IUserRepository,
    UserRecord,
    get_user_repository,
)
from vulnify.rate_limiter import login_rate_limiter
from vulnify.schemas import LoginRequest, RegisterRequest, UserResponse
from vulnify.security import (
    create_session_jwt,
    hash_password,
    verify_password_constant_time,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


def get_client_ip(request: Request) -> str:
    """Extract client IP, taking X-Forwarded-For into account if present."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def _issue_session_cookie(
    response: Response,
    user_record: UserRecord,
    settings: Settings,
) -> UserResponse:
    """Issue authenticated session cookie and return UserResponse."""
    token = create_session_jwt(
        user_id=user_record.id,
        email=user_record.email,
        role=user_record.role,
        secret=settings.SESSION_SECRET,
        ttl_minutes=settings.SESSION_TTL_MINUTES,
    )
    response.set_cookie(
        key=COOKIE_SESSION_NAME,
        value=token,
        httponly=True,
        path="/",
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        max_age=settings.SESSION_TTL_MINUTES * 60,
    )
    return UserResponse(
        id=user_record.id,
        email=user_record.email,
        name=user_record.name,
        role=user_record.role,
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
)
async def register(
    user_data: RegisterRequest,
    response: Response,
    settings: Settings = Depends(get_settings),
    repo: IUserRepository = Depends(get_user_repository),
) -> UserResponse:
    """Register a new user account with default 'user' role."""
    # 1. Enforce unique email
    existing_user = repo.get_by_email(user_data.email)
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    # 2. Hash password securely with Argon2id (never store plaintext)
    pw_hash = hash_password(user_data.password)

    # 3. Create user record with default 'user' role (prevent privilege escalation)
    user_record = repo.create_user(
        email=user_data.email,
        name=user_data.name,
        password_hash=pw_hash,
        role="user",
    )

    # 4. Issue authenticated session cookie on successful registration
    return _issue_session_cookie(response, user_record, settings)


@router.post(
    "/login",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="User login",
)
async def login(
    credentials: LoginRequest,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    repo: IUserRepository = Depends(get_user_repository),
) -> UserResponse:
    """Authenticate user, rate-limit failures, and issue httpOnly session cookie."""
    client_ip = get_client_ip(request)

    # 1. Check sliding window rate limit
    retry_after = login_rate_limiter.check_rate_limit(client_ip, credentials.email)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many attempts. Try again in {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )

    # 2. Look up user by email
    user_record = repo.get_by_email(credentials.email)

    # 3. Verify credentials in constant time (against dummy hash if user does not exist)
    is_valid = verify_password_constant_time(
        provided_password=credentials.password,
        expected_hash=user_record.password_hash if user_record else None,
    )

    if not is_valid or user_record is None:
        login_rate_limiter.record_failure(client_ip, credentials.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    # 4. Successful authentication: reset rate limiter for this user/ip
    login_rate_limiter.record_success(client_ip, credentials.email)

    # 5. Issue authenticated session cookie on successful login
    return _issue_session_cookie(response, user_record, settings)


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
)
async def me(current_user: UserResponse = Depends(require_auth)) -> UserResponse:
    """Return the profile of the currently authenticated user."""
    return current_user


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="User logout",
)
async def logout(
    response: Response,
    settings: Settings = Depends(get_settings),
) -> None:
    """Clear session cookie and log out."""
    response.delete_cookie(
        key=COOKIE_SESSION_NAME,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
    )
