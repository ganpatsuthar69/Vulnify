"""Security utilities: Argon2id password hashing/verification and JWT tokens."""

from datetime import datetime, timedelta, timezone
from typing import Any
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt

# Argon2id password hasher instance
_hasher = PasswordHasher()

# Precomputed dummy hash generated once at module load to ensure identical verification cost
_DUMMY_HASH = _hasher.hash("dummy_constant_time_verification_value")


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _hasher.hash(password)


def verify_password_constant_time(
    provided_password: str,
    expected_hash: str | None,
) -> bool:
    """Verify a user password with constant-time behavior.

    If expected_hash is None (e.g. email not found in database), verifies against
    a dummy hash to prevent timing attacks that enumerate registered emails.
    """
    target_hash = expected_hash if expected_hash is not None else _DUMMY_HASH

    try:
        _hasher.verify(target_hash, provided_password)
        password_valid = True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        password_valid = False

    return (expected_hash is not None) and password_valid


def create_session_jwt(
    user_id: str,
    email: str,
    role: str,
    secret: str,
    ttl_minutes: int,
) -> str:
    """Create a signed HS256 JWT for session authentication."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ttl_minutes)

    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_session_jwt(token: str, secret: str) -> dict[str, Any]:
    """Decode and validate a session JWT. Raises PyJWTError on failure."""
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        options={"require": ["sub", "email", "role", "iat", "exp"]},
    )
