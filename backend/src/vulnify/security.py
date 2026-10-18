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


def derive_encryption_key(secret: str | None = None) -> bytes:
    """Derive a 256-bit symmetric encryption key from a secret string."""
    import hashlib
    from vulnify.config import get_settings

    source = secret or get_settings().SESSION_SECRET
    return hashlib.sha256(source.encode("utf-8")).digest()


def encrypt_secret(plaintext: str, secret_key: str | None = None) -> str:
    """Encrypt a secret string using AES-256-GCM authenticated encryption.

    Returns a versioned, armored ciphertext string:
    'enc:v1:<base64_nonce>:<base64_ciphertext>'
    """
    if not plaintext:
        return ""

    import base64
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = derive_encryption_key(secret_key)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    nonce_b64 = base64.urlsafe_b64encode(nonce).decode("ascii")
    ct_b64 = base64.urlsafe_b64encode(ciphertext).decode("ascii")
    return f"enc:v1:{nonce_b64}:{ct_b64}"


def decrypt_secret(armored_text: str, secret_key: str | None = None) -> str:
    """Decrypt an AES-256-GCM armored secret string.

    If the string is not encrypted (e.g. legacy plain text), returns it unchanged.
    """
    if not armored_text:
        return ""
    if not armored_text.startswith("enc:v1:"):
        return armored_text

    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    parts = armored_text.split(":")
    if len(parts) != 4:
        raise ValueError("Invalid encrypted secret format.")

    _, _, nonce_b64, ct_b64 = parts
    key = derive_encryption_key(secret_key)
    aesgcm = AESGCM(key)
    nonce = base64.urlsafe_b64decode(nonce_b64.encode("ascii"))
    ciphertext = base64.urlsafe_b64decode(ct_b64.encode("ascii"))
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted.decode("utf-8")
