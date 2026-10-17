"""Main FastAPI application entry point for Vulnify."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from vulnify.config import Settings, get_settings
from vulnify.routers import admin, auth, health

CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class CSRFMiddleware(BaseHTTPMiddleware):
    """Enforces X-Requested-With header and validates Origin for state-changing HTTP requests."""

    def __init__(self, app: FastAPI, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in CSRF_PROTECTED_METHODS:
            # 1. Require X-Requested-With: vulnify header
            x_requested_with = request.headers.get("x-requested-with")
            if not x_requested_with or x_requested_with.strip().lower() != "vulnify":
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Missing or invalid X-Requested-With header"},
                )

            # 2. If Origin header is present, it must be in ALLOWED_ORIGINS
            origin = request.headers.get("origin")
            if origin:
                cleaned_origin = origin.rstrip("/")
                allowed_cleaned = [o.rstrip("/") for o in self.settings.allowed_origins_list]
                if cleaned_origin not in allowed_cleaned:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": "Untrusted origin"},
                    )

        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Validate configuration on application startup.

    Refuses to start if SESSION_SECRET is missing or weak (< 32 characters).
    """
    settings = get_settings()
    if not settings.SESSION_SECRET or len(settings.SESSION_SECRET) < 32:
        raise RuntimeError("Application startup aborted: SESSION_SECRET must be at least 32 characters.")

    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory for Vulnify backend."""
    app_settings = settings or get_settings()

    app = FastAPI(
        title="Vulnify API",
        description="Graph-powered security investigation agent API with open user registration",
        version="0.2.0",
        lifespan=lifespan,
    )

    # 1. CORS Middleware: explicit origins only, allow_credentials=True, never "*"
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # 2. CSRF Middleware
    app.add_middleware(CSRFMiddleware, settings=app_settings)

    # 3. Mount Routers
    app.include_router(auth.router)
    app.include_router(health.router)
    app.include_router(admin.router)

    return app


try:
    app = create_app()
except Exception:
    # Fail-closed lifespan if required configuration is missing on server start
    @asynccontextmanager
    async def unconfigured_lifespan(_: FastAPI) -> AsyncIterator[None]:
        get_settings()
        yield

    app = FastAPI(title="Vulnify API", lifespan=unconfigured_lifespan)
