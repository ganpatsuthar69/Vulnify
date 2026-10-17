"""Standardized API error definitions, responses, and centralized exception handlers."""

import logging
from typing import Any
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import (
    http_exception_handler as default_http_exception_handler,
    request_validation_exception_handler as default_validation_handler,
)
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from vulnify.logging import generate_request_id, get_request_id

logger = logging.getLogger("vulnify")

# Stable, machine-readable error identifiers
INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
FORBIDDEN = "FORBIDDEN"
CSRF_ERROR = "CSRF_ERROR"
NOT_FOUND = "NOT_FOUND"
METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
CONFLICT = "CONFLICT"
VALIDATION_ERROR = "VALIDATION_ERROR"
RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"
BAD_REQUEST = "BAD_REQUEST"

STATUS_CODE_TO_ERROR_CODE: dict[int, str] = {
    status.HTTP_400_BAD_REQUEST: BAD_REQUEST,
    status.HTTP_401_UNAUTHORIZED: AUTHENTICATION_REQUIRED,
    status.HTTP_403_FORBIDDEN: FORBIDDEN,
    status.HTTP_404_NOT_FOUND: NOT_FOUND,
    status.HTTP_405_METHOD_NOT_ALLOWED: METHOD_NOT_ALLOWED,
    status.HTTP_409_CONFLICT: CONFLICT,
    422: VALIDATION_ERROR,
    status.HTTP_429_TOO_MANY_REQUESTS: RATE_LIMIT_EXCEEDED,
    status.HTTP_500_INTERNAL_SERVER_ERROR: INTERNAL_SERVER_ERROR,
    status.HTTP_502_BAD_GATEWAY: "BAD_GATEWAY",
    status.HTTP_503_SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
    status.HTTP_504_GATEWAY_TIMEOUT: "GATEWAY_TIMEOUT",
}


class AppException(Exception):
    """Base application exception supporting explicit machine-readable code, status, and headers."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.headers = headers or {}


def get_error_code_for_status(status_code: int) -> str:
    """Map standard HTTP status code to default machine-readable code."""
    return STATUS_CODE_TO_ERROR_CODE.get(status_code, "UNKNOWN_ERROR")


def create_error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Construct a standardized API error response ensuring request ID consistency."""
    request_id = getattr(request.state, "request_id", None) or get_request_id() or generate_request_id()

    # Track error code on request state for access logging
    request.state.error_code = code

    resp_headers: dict[str, str] = {"X-Request-ID": request_id}
    if headers:
        for k, v in headers.items():
            if k.lower() != "x-request-id":
                resp_headers[k] = v

    return JSONResponse(
        status_code=status_code,
        content={
            "code": code,
            "message": message,
            "request_id": request_id,
        },
        headers=resp_headers,
    )


def is_api_request(request: Request) -> bool:
    """Determine whether a request belongs to the API surface rather than documentation assets."""
    path = request.url.path
    # Exempt OpenAPI / Swagger documentation from custom error JSON
    if path in ("/docs", "/redoc", "/openapi.json"):
        return False
    return True


def format_validation_error(exc: RequestValidationError) -> str:
    """Produce clean, safe validation message without leaking internal models or sensitive payloads."""
    messages: list[str] = []
    for err in exc.errors():
        loc = err.get("loc", ())
        field = ".".join(str(p) for p in loc if p not in ("body", "query", "path", "headers"))
        msg = err.get("msg", "Invalid value.")
        if field:
            messages.append(f"{field}: {msg}")
        else:
            messages.append(msg)

    return "; ".join(messages) if messages else "Invalid request data."


async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    """Handle custom application exceptions."""
    return create_error_response(
        request=request,
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        headers=exc.headers,
    )


async def http_exception_handler_override(request: Request, exc: StarletteHTTPException) -> Response:
    """Handle Starlette and FastAPI HTTPExceptions, ensuring standardized error format on API routes."""
    if not is_api_request(request):
        return await default_http_exception_handler(request, exc)

    # If detail is structured with code and message, respect it
    if isinstance(exc.detail, dict):
        code = exc.detail.get("code", get_error_code_for_status(exc.status_code))
        message = exc.detail.get("message", "An error occurred.")
    else:
        detail_str = str(exc.detail) if exc.detail is not None else ""
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            if "invalid email or password" in detail_str.lower():
                code = INVALID_CREDENTIALS
                message = "Invalid email or password."
            else:
                code = AUTHENTICATION_REQUIRED
                message = detail_str or "Authentication required."
        elif exc.status_code == status.HTTP_403_FORBIDDEN:
            lower = detail_str.lower()
            if "csrf" in lower or "origin" in lower or "x-requested-with" in lower:
                code = CSRF_ERROR
                message = detail_str
            else:
                code = FORBIDDEN
                message = detail_str or "Access forbidden."
        elif exc.status_code == status.HTTP_404_NOT_FOUND:
            code = NOT_FOUND
            message = "The requested resource was not found." if detail_str == "Not Found" else detail_str
        elif exc.status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
            code = METHOD_NOT_ALLOWED
            message = "Method not allowed for this endpoint." if detail_str == "Method Not Allowed" else detail_str
        elif exc.status_code == status.HTTP_409_CONFLICT:
            code = CONFLICT
            message = detail_str or "A conflict occurred with an existing resource."
        elif exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            code = RATE_LIMIT_EXCEEDED
            message = detail_str or "Too many requests. Please try again later."
        elif exc.status_code >= 500:
            code = INTERNAL_SERVER_ERROR
            message = "An unexpected error occurred."
        else:
            code = get_error_code_for_status(exc.status_code)
            message = detail_str or "An error occurred."

    return create_error_response(
        request=request,
        status_code=exc.status_code,
        code=code,
        message=message,
        headers=getattr(exc, "headers", None),
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> Response:
    """Handle Pydantic validation errors safely without exposing secrets."""
    if not is_api_request(request):
        return await default_validation_handler(request, exc)

    message = format_validation_error(exc)
    return create_error_response(
        request=request,
        status_code=422,
        code=VALIDATION_ERROR,
        message=message,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    """Catch-all for unhandled server exceptions, logging diagnostic traceback while returning safe error."""
    request_id = getattr(request.state, "request_id", None) or get_request_id() or generate_request_id()
    method = request.method
    safe_path = request.url.path

    logger.error(
        "Unhandled server error on %s %s: %s",
        method,
        safe_path,
        exc,
        exc_info=True,
        extra={
            "method": method,
            "path": safe_path,
            "status_code": 500,
            "error_code": INTERNAL_SERVER_ERROR,
            "request_id": request_id,
        },
    )

    return create_error_response(
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code=INTERNAL_SERVER_ERROR,
        message="An unexpected error occurred.",
    )
