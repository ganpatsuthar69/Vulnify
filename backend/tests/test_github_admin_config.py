"""Tests for US-506: GitHub Integration Admin Configuration UI & Backend Service.

Acceptance Criteria verified:
1. Admin sets target repository (owner/repo) and issues go to the right place (US-506).
2. Owner and repo name are validated against token's access with GitHub REST API (US-506).
3. The personal access token is never displayed or returned in API responses (US-506).
4. Misconfiguration blocks issue creation with a clear message (US-506).
5. Non-administrators are forbidden from altering integration configuration (RBAC).
6. Token rotation: updating configuration without a new token preserves existing token.
7. Project-level repository configuration override.
"""

from typing import Any
import httpx
from httpx import AsyncClient, Response
import pytest

from vulnify.config import Settings
from vulnify.graph.github_config_repository import InMemoryGitHubConfigRepository
from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from tests.conftest import ADMIN_USER, authenticate_client

STANDARD_USER = {
    "id": "regular-user-uuid",
    "name": "Standard Developer",
    "email": "dev@vulnify.local",
    "role": "user",
}


def _seed_test_env(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-cfg-1",
    project_name: str = "Config Test Project",
) -> ProjectRecord:
    # Seed Admin User
    mock_user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    admin_user = mock_user_repo.get_by_email(ADMIN_USER["email"])
    if admin_user:
        admin_user.id = ADMIN_USER["id"]
        mock_user_repo._users_by_id[ADMIN_USER["id"]] = admin_user

    # Seed Standard User
    mock_user_repo.create_user(
        email=STANDARD_USER["email"],
        name=STANDARD_USER["name"],
        password_hash="mock_hash",
        role=STANDARD_USER["role"],
    )
    std_user = mock_user_repo.get_by_email(STANDARD_USER["email"])
    if std_user:
        std_user.id = STANDARD_USER["id"]
        mock_user_repo._users_by_id[STANDARD_USER["id"]] = std_user

    proj = ProjectRecord(
        id=project_id,
        name=project_name,
        normalized_name=project_name.lower(),
        ecosystem="npm",
        description="Test project for GitHub config",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _seed_finding(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    project_id: str,
    finding_id: str = "find-cfg-001",
    package_name: str = "axios",
    package_version: str = "0.21.1",
    fixed_version: str = "0.21.2",
) -> None:
    adv_id = "GHSA-c4w7-xm78-47vh"
    f_dict = {
        "id": finding_id,
        "project_id": project_id,
        "service_id": f"{project_id}:api",
        "service_name": "api",
        "advisory_id": adv_id,
        "advisory_summary": "SSRF in axios",
        "advisory_details": "Axios vulnerability details",
        "severity": "HIGH",
        "source_url": f"https://github.com/advisories/{adv_id}",
        "retrieved_at": 1700000000,
        "aliases": ["CVE-2021-3749"],
        "package_version_id": f"npm:{package_name}@{package_version}",
        "package_name": package_name,
        "package_version": package_version,
        "ecosystem": "npm",
        "match_reason": "Version in range",
        "reason_code": "WITHIN_AFFECTED_RANGE",
        "matched_range": "< 0.21.2",
        "fixed_version": fixed_version,
        "advisory_fixed_versions": [fixed_version],
        "priority": "High",
        "status": "open",
        "path_depth": 1,
        "path_status": "path_found",
    }
    if project_id not in mock_vuln_repo.findings_override:
        mock_vuln_repo.findings_override[project_id] = []
    mock_vuln_repo.findings_override[project_id].append(f_dict)
    mock_vuln_repo.vulnerabilities_data[adv_id] = {
        "id": adv_id,
        "details": f_dict["advisory_details"],
        "summary": f_dict["advisory_summary"],
        "fixed_version": fixed_version,
    }


# =====================================================================
# Tests: Authentication & Authorization (RBAC)
# =====================================================================


@pytest.mark.asyncio
async def test_admin_config_requires_authentication(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """Unauthenticated requests to admin GitHub config endpoints fail with 401."""
    _seed_test_env(mock_user_repo, mock_project_repo)

    # 1. GET config
    resp = await client.get("/api/admin/github-config")
    assert resp.status_code == 401

    # 2. POST update config
    resp = await client.post(
        "/api/admin/github-config",
        json={"owner": "my-org", "repo": "my-repo", "token": "ghp_secret"},
    )
    assert resp.status_code == 401

    # 3. POST validate
    resp = await client.post(
        "/api/admin/github-config/validate",
        json={"owner": "my-org", "repo": "my-repo", "token": "ghp_secret"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_admin_config_forbidden_for_non_admin_users(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """Standard authenticated users without admin role get 403 Forbidden."""
    _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client, STANDARD_USER)

    # 1. GET config
    resp = await client.get("/api/admin/github-config")
    assert resp.status_code == 403
    assert "Administrator access required" in resp.json()["message"]

    # 2. POST update
    resp = await client.post(
        "/api/admin/github-config",
        json={"owner": "my-org", "repo": "my-repo", "token": "ghp_secret"},
    )
    assert resp.status_code == 403

    # 3. POST validate
    resp = await client.post(
        "/api/admin/github-config/validate",
        json={"owner": "my-org", "repo": "my-repo", "token": "ghp_secret"},
    )
    assert resp.status_code == 403


# =====================================================================
# Tests: Validation against GitHub REST API (US-506 AC-1)
# =====================================================================


@pytest.mark.asyncio
async def test_validate_target_repo_success(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-1: Target repo and owner are validated against token access via GitHub REST API."""
    _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client, ADMIN_USER)

    orig_get = httpx.AsyncClient.get

    async def mock_get(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url) and "repos/my-org/production-app" in str(url):
            return Response(
                status_code=200,
                json={
                    "id": 12345,
                    "name": "production-app",
                    "full_name": "my-org/production-app",
                    "private": True,
                    "has_issues": True,
                    "permissions": {"admin": True, "push": True, "pull": True},
                },
            )
        return await orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    resp = await client.post(
        "/api/admin/github-config/validate",
        json={"owner": "my-org", "repo": "production-app", "token": "ghp_valid_test_token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["status"] == "valid"
    assert data["target_repo"] == "my-org/production-app"
    assert data["has_issues_enabled"] is True
    assert data["has_write_access"] is True
    assert "token" not in data  # Token never displayed!


@pytest.mark.asyncio
async def test_validate_target_repo_unauthorized_token(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-1: Token validation fails with 401 if GitHub rejects the token."""
    _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client, ADMIN_USER)

    orig_get = httpx.AsyncClient.get

    async def mock_get_401(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            return Response(status_code=401, json={"message": "Bad credentials"})
        return await orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get_401)

    resp = await client.post(
        "/api/admin/github-config/validate",
        json={"owner": "my-org", "repo": "production-app", "token": "ghp_bad_token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["status"] == "unauthorized"
    assert "invalid, expired, or revoked" in data["message"]


@pytest.mark.asyncio
async def test_validate_target_repo_not_found(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-1: Repository not found (or private without access) returns clear error."""
    _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client, ADMIN_USER)

    orig_get = httpx.AsyncClient.get

    async def mock_get_404(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            return Response(status_code=404, json={"message": "Not Found"})
        return await orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get_404)

    resp = await client.post(
        "/api/admin/github-config/validate",
        json={"owner": "nonexistent-org", "repo": "nonexistent-repo", "token": "ghp_valid"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["status"] == "not_found"
    assert "not found, or the token does not have read access" in data["message"]


@pytest.mark.asyncio
async def test_validate_target_repo_issues_disabled(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-1: Target repo with issues disabled is detected and warned."""
    _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client, ADMIN_USER)

    orig_get = httpx.AsyncClient.get

    async def mock_get_issues_disabled(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            return Response(
                status_code=200,
                json={
                    "id": 999,
                    "name": "disabled-issues-repo",
                    "full_name": "my-org/disabled-issues-repo",
                    "has_issues": False,
                    "permissions": {"push": True},
                },
            )
        return await orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get_issues_disabled)

    resp = await client.post(
        "/api/admin/github-config/validate",
        json={"owner": "my-org", "repo": "disabled-issues-repo", "token": "ghp_valid"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["status"] == "issues_disabled"
    assert "Issues feature is disabled" in data["message"]


@pytest.mark.asyncio
async def test_validate_target_repo_format_error(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """Invalid owner/repo format returns validation error."""
    _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client, ADMIN_USER)

    resp = await client.post(
        "/api/admin/github-config/validate",
        json={"owner": "invalid owner with spaces", "repo": "repo/with/extra/slashes", "token": "ghp_token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["status"] == "invalid_format"


# =====================================================================
# Tests: Update Configuration, Persistence & Token Masking (US-506 AC-1)
# =====================================================================


@pytest.mark.asyncio
async def test_admin_update_config_and_token_never_displayed(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-1: Target repo is configured; token is encrypted and never displayed or returned in API."""
    _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client, ADMIN_USER)

    orig_get = httpx.AsyncClient.get

    async def mock_get_ok(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            return Response(
                status_code=200,
                json={"has_issues": True, "permissions": {"push": True}},
            )
        return await orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get_ok)

    # 1. Update configuration with token
    update_resp = await client.post(
        "/api/admin/github-config",
        json={
            "owner": "team-sec",
            "repo": "vuln-tracker",
            "token": "ghp_super_secret_token_12345",
            "validate_before_save": True,
        },
    )
    assert update_resp.status_code == 200
    res_data = update_resp.json()
    assert res_data["configured"] is True
    assert res_data["owner"] == "team-sec"
    assert res_data["repo"] == "vuln-tracker"
    assert res_data["target_repo"] == "team-sec/vuln-tracker"
    assert res_data["has_token"] is True
    assert res_data["validation_status"] == "valid"
    assert "token" not in res_data  # Token is NEVER displayed!
    assert "ghp_super_secret" not in str(res_data)

    # 2. GET configuration verifies persistence and masking
    get_resp = await client.get("/api/admin/github-config")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["target_repo"] == "team-sec/vuln-tracker"
    assert get_data["has_token"] is True
    assert "token" not in get_data
    assert "ghp_super_secret" not in str(get_data)

    # 3. Update repo name without providing a new token preserves existing encrypted token
    update_repo_only = await client.post(
        "/api/admin/github-config",
        json={
            "owner": "team-sec",
            "repo": "new-remediation-repo",
            "token": None,  # Keep existing token
            "validate_before_save": True,
        },
    )
    assert update_repo_only.status_code == 200
    assert update_repo_only.json()["target_repo"] == "team-sec/new-remediation-repo"
    assert update_repo_only.json()["has_token"] is True


# =====================================================================
# Tests: Misconfiguration Blocks Issue Creation (US-506 AC-2)
# =====================================================================


@pytest.mark.asyncio
async def test_misconfiguration_blocks_issue_creation_with_clear_message(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    mock_github_config_repo: InMemoryGitHubConfigRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-2: Misconfiguration blocks issue creation with a clear message."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-misconfig-1")
    authenticate_client(client, ADMIN_USER)
    _seed_finding(mock_vuln_repo, project.id, finding_id="find-misc-1")

    # Set up a misconfigured record in the repository with a token that is marked invalid
    from vulnify.graph.github_config_repository import GitHubConfigRecord
    from vulnify.security import encrypt_secret

    enc_token = encrypt_secret("ghp_invalid_token", test_settings.SESSION_SECRET)
    bad_config = GitHubConfigRecord(
        id="global",
        owner="broken-org",
        repo="inaccessible-repo",
        target_repo="broken-org/inaccessible-repo",
        encrypted_token=enc_token,
        api_base_url="https://api.github.com",
        validation_status="invalid",
        validation_message="Repository 'broken-org/inaccessible-repo' was not found or token lacks access (HTTP 404).",
        last_validated_at=1700000000,
        updated_at=1700000000,
        updated_by="admin@vulnify.local",
    )
    mock_github_config_repo.upsert_config(bad_config)

    # 1. Preview shows misconfiguration warning
    prev_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-misc-1/github-issues/preview",
        json={},
    )
    assert prev_resp.status_code == 200
    pdata = prev_resp.json()
    assert pdata["can_submit"] is False
    assert "misconfigured" in pdata["configuration_warning"].lower()

    # 2. Attempting to create issue is blocked with 400 Bad Request and clear error message
    create_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-misc-1/github-issues",
        json={
            "plan_hash": pdata["plan_hash"],
            "title": pdata["title"],
            "body": pdata["body"],
            "target_repo": pdata["target_repo"],
            "confirmed": True,
        },
    )
    assert create_resp.status_code == 400
    msg = create_resp.json()["message"]
    assert "misconfigured" in msg.lower()
    assert "broken-org/inaccessible-repo" in msg or "not found" in msg


# =====================================================================
# Tests: Project-Scoped Configuration & Issue Creation Routing (US-506)
# =====================================================================


@pytest.mark.asyncio
async def test_project_scoped_github_config_routes_issues_to_right_place(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admin sets project-level target repo; previews and issues go to that repository."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-custom-target")
    authenticate_client(client, ADMIN_USER)
    _seed_finding(mock_vuln_repo, project.id, finding_id="find-custom-1")

    orig_get = httpx.AsyncClient.get
    orig_post = httpx.AsyncClient.post

    async def mock_github_get(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url) and "repos/project-specific-org/custom-repo" in str(url):
            return Response(
                status_code=200,
                json={"has_issues": True, "permissions": {"push": True}},
            )
        return await orig_get(self, url, *args, **kwargs)

    async def mock_github_post(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url) and "repos/project-specific-org/custom-repo/issues" in str(url):
            return Response(
                status_code=201,
                json={"number": 42, "html_url": "https://github.com/project-specific-org/custom-repo/issues/42"},
            )
        return await orig_post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_github_get)
    monkeypatch.setattr(httpx.AsyncClient, "post", mock_github_post)

    # 1. Update project-level GitHub configuration
    proj_cfg_resp = await client.put(
        f"/api/projects/{project.id}/github/config",
        json={
            "owner": "project-specific-org",
            "repo": "custom-repo",
            "token": "ghp_project_token_secret",
            "validate_before_save": True,
        },
    )
    assert proj_cfg_resp.status_code == 200
    assert proj_cfg_resp.json()["target_repo"] == "project-specific-org/custom-repo"
    assert proj_cfg_resp.json()["has_token"] is True

    # 2. Preview targets the project-specific configured repository
    prev = await client.post(
        f"/api/projects/{project.id}/findings/find-custom-1/github-issues/preview",
        json={},
    )
    assert prev.status_code == 200
    pdata = prev.json()
    assert pdata["target_repo"] == "project-specific-org/custom-repo"
    assert pdata["can_submit"] is True

    # 3. Create issue succeeds in project-specific repo
    create_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-custom-1/github-issues",
        json={
            "plan_hash": pdata["plan_hash"],
            "title": pdata["title"],
            "body": pdata["body"],
            "target_repo": "project-specific-org/custom-repo",
            "confirmed": True,
        },
    )
    assert create_resp.status_code == 200
    cdata = create_resp.json()
    assert cdata["target_repo"] == "project-specific-org/custom-repo"
    assert cdata["issue_number"] == 42
    assert "https://github.com/project-specific-org/custom-repo/issues/42" in cdata["issue_url"]
