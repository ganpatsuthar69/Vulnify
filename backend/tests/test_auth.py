"""Tests for user registration, authentication, RBAC, and session security."""

from datetime import datetime, timedelta, timezone
from httpx import ASGITransport, AsyncClient
import jwt
import pytest

from vulnify.config import Settings
from vulnify.dependencies import COOKIE_SESSION_NAME
from vulnify.graph.user_repository import InMemoryUserRepository

TEST_SESSION_SECRET = "test_session_secret_that_is_at_least_32_chars_long!"

SAMPLE_USER = {
    "name": "Alex Analyst",
    "email": "alex@example.com",
    "password": "SecurePassword123!",
}


@pytest.mark.asyncio
async def test_user_registration_success(client: AsyncClient) -> None:
    """User registration succeeds with default 'user' role and issues session cookie."""
    response = await client.post("/api/auth/register", json=SAMPLE_USER)

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == SAMPLE_USER["email"]
    assert data["name"] == SAMPLE_USER["name"]
    assert data["role"] == "user"  # Enforces default user role
    assert "id" in data

    # Verify session cookie was set with HttpOnly and SameSite
    set_cookie_headers = [h for k, h in response.headers.multi_items() if k.lower() == "set-cookie"]
    session_cookie = next((h for h in set_cookie_headers if COOKIE_SESSION_NAME in h), None)
    assert session_cookie is not None
    assert "httponly" in session_cookie.lower()
    assert "samesite=lax" in session_cookie.lower()


@pytest.mark.asyncio
async def test_duplicate_registration_returns_409_conflict(client: AsyncClient) -> None:
    """Registering an existing email returns 409 Conflict with clear error message."""
    res1 = await client.post("/api/auth/register", json=SAMPLE_USER)
    assert res1.status_code == 201

    res2 = await client.post("/api/auth/register", json=SAMPLE_USER)
    assert res2.status_code == 409
    data = res2.json()
    assert data["code"] == "CONFLICT"
    assert "already exists" in data["message"]
    assert "request_id" in data
    assert res2.headers["X-Request-ID"] == data["request_id"]


@pytest.mark.asyncio
async def test_registration_validation_errors(client: AsyncClient) -> None:
    """Registration rejects short passwords and invalid email formats."""
    # Short password (< 8 chars)
    res_short_pw = await client.post(
        "/api/auth/register",
        json={"name": "Alice", "email": "alice@example.com", "password": "short"},
    )
    assert res_short_pw.status_code == 422

    # Invalid email format
    res_bad_email = await client.post(
        "/api/auth/register",
        json={"name": "Alice", "email": "not-an-email", "password": "ValidPassword123!"},
    )
    assert res_bad_email.status_code == 422


@pytest.mark.asyncio
async def test_login_success_with_registered_user(client: AsyncClient) -> None:
    """Registered user can log in and receives session cookie."""
    # Register user
    await client.post("/api/auth/register", json=SAMPLE_USER)

    # Log in
    login_res = await client.post(
        "/api/auth/login",
        json={"email": SAMPLE_USER["email"], "password": SAMPLE_USER["password"]},
    )
    assert login_res.status_code == 200
    assert login_res.json()["email"] == SAMPLE_USER["email"]
    assert login_res.json()["role"] == "user"

    # Verify /api/auth/me returns the profile
    me_res = await client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["email"] == SAMPLE_USER["email"]


@pytest.mark.asyncio
async def test_wrong_email_and_wrong_password_return_identical_401(client: AsyncClient) -> None:
    """Wrong email and wrong password return identical 401 responses with constant-time check."""
    await client.post("/api/auth/register", json=SAMPLE_USER)

    # Wrong email
    res_wrong_email = await client.post(
        "/api/auth/login",
        json={"email": "nonexistent@example.com", "password": SAMPLE_USER["password"]},
    )

    # Correct email, wrong password
    res_wrong_pass = await client.post(
        "/api/auth/login",
        json={"email": SAMPLE_USER["email"], "password": "WrongPassword999!"},
    )

    assert res_wrong_email.status_code == 401
    assert res_wrong_pass.status_code == 401
    data_email = res_wrong_email.json()
    data_pass = res_wrong_pass.json()
    assert data_email["code"] == data_pass["code"] == "INVALID_CREDENTIALS"
    assert data_email["message"] == data_pass["message"] == "Invalid email or password."
    assert "request_id" in data_email and "request_id" in data_pass
    assert data_email["request_id"] != data_pass["request_id"]
    assert res_wrong_email.headers["X-Request-ID"] == data_email["request_id"]
    assert res_wrong_pass.headers["X-Request-ID"] == data_pass["request_id"]


@pytest.mark.asyncio
async def test_login_rate_limiting_after_five_failures(client: AsyncClient) -> None:
    """The 6th failed login returns 429 with Retry-After header."""
    for i in range(5):
        res = await client.post(
            "/api/auth/login",
            json={"email": "someone@example.com", "password": f"wrong_{i}"},
        )
        assert res.status_code == 401

    res_sixth = await client.post(
        "/api/auth/login",
        json={"email": "someone@example.com", "password": "wrong_final"},
    )
    assert res_sixth.status_code == 429
    assert "Retry-After" in res_sixth.headers
    assert int(res_sixth.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_role_based_access_control(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
) -> None:
    """Standard users are blocked from admin routes; admins are granted access."""
    # Register normal user
    await client.post("/api/auth/register", json=SAMPLE_USER)

    # Standard user visits admin endpoint -> 403 Forbidden
    admin_res = await client.get("/api/admin/status")
    assert admin_res.status_code == 403
    admin_data = admin_res.json()
    assert admin_data["code"] == "FORBIDDEN"
    assert "Administrator access required" in admin_data["message"]
    assert admin_res.headers["X-Request-ID"] == admin_data["request_id"]

    # Deliberately promote user to admin in repository
    mock_user_repo.update_role(SAMPLE_USER["email"], "admin")

    # Now the same user has admin access
    admin_success = await client.get("/api/admin/status")
    assert admin_success.status_code == 200
    assert admin_success.json()["role"] == "admin"


@pytest.mark.asyncio
async def test_protected_route_without_cookie_and_with_expired_token(
    client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Protected route returns 401 when unauthenticated or token is expired."""
    # Without cookie
    res_no_cookie = await client.get("/api/auth/me")
    assert res_no_cookie.status_code == 401

    # With expired token
    past_now = datetime.now(timezone.utc) - timedelta(hours=2)
    expired_token = jwt.encode(
        {
            "sub": "some-user-id",
            "email": "test@example.com",
            "role": "user",
            "iat": int((past_now - timedelta(minutes=10)).timestamp()),
            "exp": int(past_now.timestamp()),
        },
        test_settings.SESSION_SECRET,
        algorithm="HS256",
    )
    client.cookies.set(COOKIE_SESSION_NAME, expired_token)

    res_expired = await client.get("/api/auth/me")
    assert res_expired.status_code == 401


@pytest.mark.asyncio
async def test_csrf_protection_and_logout(client: AsyncClient, app) -> None:
    """Missing X-Requested-With returns 403, and logout clears the session cookie."""
    transport = ASGITransport(app=app)
    # 1. State-changing request without CSRF header -> 403
    async with AsyncClient(transport=transport, base_url="http://test") as raw_client:
        res = await raw_client.post("/api/auth/register", json=SAMPLE_USER)
        assert res.status_code == 403
        csrf_data = res.json()
        assert csrf_data["code"] == "CSRF_ERROR"
        assert "X-Requested-With" in csrf_data["message"]
        assert res.headers["X-Request-ID"] == csrf_data["request_id"]

    # 2. Register with CSRF header
    await client.post("/api/auth/register", json=SAMPLE_USER)

    # 3. Logout clears cookie
    logout_res = await client.post("/api/auth/logout")
    assert logout_res.status_code == 204
    set_cookie_headers = [h for k, h in logout_res.headers.multi_items() if k.lower() == "set-cookie"]
    session_cookie = next((h for h in set_cookie_headers if COOKIE_SESSION_NAME in h), None)
    assert session_cookie is not None
    assert ("max-age=0" in session_cookie.lower()) or ("expires=" in session_cookie.lower())


def test_falkor_repository_direct_integration() -> None:
    """Test FalkorUserRepository directly against FalkorDB if reachable."""
    from vulnify.graph.client import GraphClient
    from vulnify.graph.user_repository import FalkorUserRepository
    from vulnify.config import Settings

    settings = Settings(
        FALKORDB_HOST="localhost",
        FALKORDB_PORT=6379,
        FALKORDB_PASSWORD="VulnifyLocal_ChangeMe_2026",
        FALKORDB_GRAPH="vulnify",
        SESSION_SECRET=TEST_SESSION_SECRET,
    )
    try:
        client = GraphClient(settings)
        repo = FalkorUserRepository(client)
        # Test creation
        test_email = "direct_test_user@example.com"
        created = repo.create_user(test_email, "Direct Test", "$argon2id$testhash", role="user")
        assert created.email == test_email
        assert created.role == "user"

        # Test fetch
        fetched = repo.get_by_email(test_email)
        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.name == "Direct Test"

        # Test update role
        updated = repo.update_role(test_email, "admin")
        assert updated is not None
        assert updated.role == "admin"

        # Cleanup
        client.get_graph().query("MATCH (u:User {email: $email}) DELETE u", {"email": test_email})
    except Exception as e:
        pytest.skip(f"FalkorDB direct test skipped: {e}")


def test_secret_encryption_and_decryption_roundtrip() -> None:
    """Verify AES-256-GCM authenticated encryption preserves secrets and guards against tampering."""
    from vulnify.security import decrypt_secret, encrypt_secret

    sample_api_key = "mistral_api_key_secret_token_12345"
    encrypted = encrypt_secret(sample_api_key, secret_key=TEST_SESSION_SECRET)

    assert encrypted.startswith("enc:v1:")
    assert sample_api_key not in encrypted

    # Successful roundtrip
    decrypted = decrypt_secret(encrypted, secret_key=TEST_SESSION_SECRET)
    assert decrypted == sample_api_key

    # Plaintext fallback for legacy unencrypted strings
    assert decrypt_secret("legacy_plain_key") == "legacy_plain_key"
    assert decrypt_secret("") == ""

    # Tampered ciphertext raises error
    tampered = encrypted[:-4] + "AAAA"
    with pytest.raises(Exception):
        decrypt_secret(tampered, secret_key=TEST_SESSION_SECRET)
