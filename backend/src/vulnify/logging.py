"""Structured logging and Request ID handling for Vulnify."""

import contextvars
from datetime import datetime, timezone
import json
import logging
import re
import time
from typing import Any
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

# Context variable for request ID tracking across async tasks
request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")

# Safe request ID validation pattern: 1-64 alphanumeric, dash, or underscore characters
SAFE_REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

SENSITIVE_FIELD_NAMES = {
    "password",
    "password_hash",
    "secret",
    "session_secret",
    "token",
    "access_token",
    "cookie",
    "cookies",
    "authorization",
    "vulnify_session",
}


def is_valid_request_id(req_id: str | None) -> bool:
    """Validate request ID against a strict character and length whitelist."""
    if not req_id:
        return False
    return bool(SAFE_REQUEST_ID_REGEX.match(req_id.strip()))


def generate_request_id() -> str:
    """Generate a collision-resistant unique request ID."""
    return f"req-{uuid.uuid4().hex[:16]}"


def get_request_id() -> str:
    """Retrieve current request ID from context variable."""
    return request_id_ctx.get()


def set_request_id(req_id: str) -> contextvars.Token[str]:
    """Set request ID in current context."""
    return request_id_ctx.set(req_id)


class RequestIdFilter(logging.Filter):
    """Logging filter that injects the current request ID into log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not getattr(record, "request_id", None):
            record.request_id = get_request_id() or "-"
        return True


class StructuredJsonFormatter(logging.Formatter):
    """JSON formatter emitting machine-readable logs with contextual request attributes."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Request ID from record or contextvar
        req_id = getattr(record, "request_id", None) or get_request_id()
        if req_id and req_id != "-":
            log_entry["request_id"] = req_id

        # Standard contextual fields if set
        for field in ("method", "path", "status_code", "error_code", "duration_ms", "client_ip"):
            val = getattr(record, field, None)
            if val is not None:
                log_entry[field] = val

        # Diagnostics for exceptions
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_logging(log_level: str = "INFO") -> None:
    """Configure structured logging on the vulnify root logger."""
    vulnify_logger = logging.getLogger("vulnify")
    vulnify_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Avoid adding duplicate handlers
    if not vulnify_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredJsonFormatter())
        handler.addFilter(RequestIdFilter())
        vulnify_logger.addHandler(handler)
        vulnify_logger.propagate = False


logger = logging.getLogger("vulnify")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Middleware managing request ID generation/validation, context propagation, and request logging."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Validate or generate request ID
        raw_header = request.headers.get("x-request-id")
        if is_valid_request_id(raw_header):
            request_id = raw_header.strip()  # type: ignore[union-attr]
        else:
            request_id = generate_request_id()

        # 2. Store in contextvar and request.state
        token = set_request_id(request_id)
        request.state.request_id = request_id

        start_time = time.perf_counter()
        safe_path = request.url.path
        method = request.method

        try:
            response = await call_next(request)
        except Exception:
            # Catch unexpected exceptions escaping to middleware level
            from vulnify.errors import create_error_response

            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                "Unhandled server error on %s %s",
                method,
                safe_path,
                exc_info=True,
                extra={
                    "method": method,
                    "path": safe_path,
                    "status_code": 500,
                    "error_code": "INTERNAL_SERVER_ERROR",
                    "duration_ms": duration_ms,
                    "request_id": request_id,
                },
            )
            response = create_error_response(
                request=request,
                status_code=500,
                code="INTERNAL_SERVER_ERROR",
                message="An unexpected error occurred.",
            )
        finally:
            request_id_ctx.reset(token)

        # 3. Ensure response header is populated
        response.headers["X-Request-ID"] = request_id

        # 4. Log HTTP completion
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        status_code = response.status_code
        extra_info: dict[str, Any] = {
            "method": method,
            "path": safe_path,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "request_id": request_id,
        }

        # Check if an error_code was attached to request state
        if hasattr(request.state, "error_code"):
            extra_info["error_code"] = request.state.error_code

        if status_code < 400:
            logger.info("HTTP request completed", extra=extra_info)
        elif status_code < 500:
            logger.warning("HTTP client error", extra=extra_info)
        else:
            logger.error("HTTP server error", extra=extra_info)

        return response
