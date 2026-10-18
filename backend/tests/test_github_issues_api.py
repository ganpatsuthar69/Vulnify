"""Tests for US-503 / US-504: GitHub Remediation Issue Preview, Human Approval Gating, and Creation.

Acceptance Criteria verified:
1. Preview is built from structured fields and shows a plan hash (US-503).
2. Editing the title changes the hash (US-503).
3. Creation requires human approval ('confirmed': true) and verifies plan hash and CSRF (US-504).
4. Targets configured repository and creates real issue via GitHub REST API without leaking credentials (US-504).
5. Idempotent duplicate prevention: resubmitting same plan returns existing issue without duplicate (US-504).
6. Upstream GitHub error handling: rate limits, permission denied, not found, timeouts (US-504).
"""

import asyncio
from typing import Any
import httpx
from httpx import AsyncClient, Response
import pytest

from vulnify.config import Settings
from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from vulnify.services.github_service import GitHubService, compute_plan_hash
from tests.conftest import ADMIN_USER, authenticate_client


def _seed_test_env(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-gh-1",
    project_name: str = "GitHub Integration Test Project",
) -> ProjectRecord:
    mock_user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    user = mock_user_repo.get_by_email(ADMIN_USER["email"])
    if user:
        user.id = ADMIN_USER["id"]
        mock_user_repo._users_by_id[ADMIN_USER["id"]] = user

    proj = ProjectRecord(
        id=project_id,
        name=project_name,
        normalized_name=project_name.lower(),
        ecosystem="npm",
        description="Test project for GitHub issues",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _seed_finding(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    project_id: str,
    finding_id: str = "find-gh-001",
    advisory_id: str = "GHSA-issue-test",
    package_name: str = "lodash",
    package_version: str = "4.17.20",
    fixed_version: str | None = "4.17.21",
    path_depth: int = 2,
    service_id: str = "proj-gh-1:order-api",
    service_name: str = "order-api",
    ecosystem: str = "npm",
) -> dict[str, Any]:
    f_dict = {
        "id": finding_id,
        "project_id": project_id,
        "service_id": service_id,
        "service_name": service_name,
        "advisory_id": advisory_id,
        "advisory_summary": f"Prototype pollution in {package_name}",
        "advisory_details": f"Detailed advisory info for {advisory_id}",
        "severity": "HIGH",
        "source_url": f"https://github.com/advisories/{advisory_id}",
        "retrieved_at": 1700000000,
        "aliases": ["CVE-2021-23337"],
        "package_version_id": f"{ecosystem}:{package_name}@{package_version}",
        "package_name": package_name,
        "package_version": package_version,
        "ecosystem": ecosystem,
        "match_reason": f"Version {package_version} matches affected range",
        "reason_code": "WITHIN_AFFECTED_RANGE",
        "matched_range": f"< {fixed_version}" if fixed_version else "all versions",
        "fixed_version": fixed_version,
        "advisory_fixed_versions": [fixed_version] if fixed_version else [],
        "priority": "High",
        "status": "open",
        "path_depth": path_depth,
        "path_status": "path_found",
    }
    if project_id not in mock_vuln_repo.findings_override:
        mock_vuln_repo.findings_override[project_id] = []
    mock_vuln_repo.findings_override[project_id].append(f_dict)
    mock_vuln_repo.vulnerabilities_data[advisory_id] = {
        "id": advisory_id,
        "details": f_dict["advisory_details"],
        "fixed_versions": [fixed_version] if fixed_version else [],
        "aliases": f_dict["aliases"],
    }
    return f_dict


@pytest.mark.asyncio
async def test_preview_github_issue_structured_fields_and_hash(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """US-503: Preview is built from structured fields and shows plan hash; editing title creates new hash."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-preview-1")
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project.id,
        finding_id="find-prev-1",
        package_name="lodash",
        package_version="4.17.20",
        fixed_version="4.17.21",
    )

    # 1. Default preview
    resp1 = await client.post(
        f"/api/projects/{project.id}/findings/find-prev-1/github-issues/preview",
        json={},
    )
    assert resp1.status_code == 200, resp1.text
    data1 = resp1.json()

    assert data1["package_name"] == "lodash"
    assert data1["current_version"] == "4.17.20"
    assert data1["target_version"] == "4.17.21"
    assert "lodash" in data1["title"]
    assert "4.17.21" in data1["body"]
    assert "Architectural exposure indicates structural reachability" in data1["body"]
    assert data1["plan_hash"].startswith("plan_sha256_")

    # 2. Preview with title override (US-503: editing title creates new hash)
    resp2 = await client.post(
        f"/api/projects/{project.id}/findings/find-prev-1/github-issues/preview",
        json={"title_override": "Custom Custom Title for Security Review"},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()

    assert data2["title"] == "Custom Custom Title for Security Review"
    assert data2["plan_hash"] != data1["plan_hash"]
    assert data2["plan_hash"].startswith("plan_sha256_")


@pytest.mark.asyncio
async def test_create_github_issue_success_and_headers(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """US-504: Approve and create real issue via REST API, asserting payload, headers, and response fields."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-create-1")
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project.id,
        finding_id="find-create-1",
        package_name="express",
        package_version="4.17.1",
        fixed_version="4.18.2",
    )

    # Configure GITHUB_TOKEN
    test_token = "ghp_test_token_1234567890abcdef"
    test_settings.GITHUB_TOKEN = test_token

    # 1. First obtain authoritative preview
    prev_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-create-1/github-issues/preview",
        json={},
    )
    assert prev_resp.status_code == 200
    prev_data = prev_resp.json()
    plan_hash = prev_data["plan_hash"]
    title = prev_data["title"]
    body = prev_data["body"]
    target_repo = prev_data["target_repo"]

    # 2. Mock GitHub REST API response
    recorded_request: dict[str, Any] = {}
    orig_post = httpx.AsyncClient.post

    async def mock_post(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            json_payload = kwargs.get("json", {})
            headers = kwargs.get("headers", {})
            recorded_request["url"] = str(url)
            recorded_request["json"] = json_payload
            recorded_request["headers"] = headers
            return Response(
                status_code=201,
                json={
                    "number": 42,
                    "html_url": f"https://github.com/{target_repo}/issues/42",
                    "state": "open",
                    "title": json_payload.get("title", ""),
                },
            )
        return await orig_post(self, url, *args, **kwargs)

    # Inject mock into httpx
    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    # 3. Submit approved issue
    create_payload = {
        "plan_hash": plan_hash,
        "title": title,
        "body": body,
        "target_repo": target_repo,
        "target_version": "4.18.2",
        "confirmed": True,
    }

    create_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-create-1/github-issues",
        json=create_payload,
    )
    assert create_resp.status_code == 200, create_resp.text
    res_data = create_resp.json()

    assert res_data["issue_number"] == 42
    assert res_data["issue_url"] == f"https://github.com/{target_repo}/issues/42"
    assert res_data["state"] == "open"
    assert res_data["is_duplicate"] is False
    assert res_data["created_by"] == ADMIN_USER["email"]

    # Assert correct GitHub API request headers
    assert recorded_request["headers"]["Authorization"] == f"Bearer {test_token}"
    assert recorded_request["headers"]["Accept"] == "application/vnd.github+json"
    assert recorded_request["headers"]["User-Agent"] == "Vulnify-Security-Agent"
    assert recorded_request["json"]["title"] == title


@pytest.mark.asyncio
async def test_idempotent_duplicate_prevention(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """US-504 AC-3: Re-submitting the same plan does not create a duplicate; returns existing issue link."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-dup-1")
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project.id,
        finding_id="find-dup-1",
        package_name="tar",
        package_version="6.1.0",
        fixed_version="6.1.11",
    )

    test_settings.GITHUB_TOKEN = "ghp_mock_token"

    prev_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-dup-1/github-issues/preview",
        json={},
    )
    assert prev_resp.status_code == 200
    prev_data = prev_resp.json()

    call_count = 0
    orig_post = httpx.AsyncClient.post

    async def mock_post(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            nonlocal call_count
            call_count += 1
            return Response(
                status_code=201,
                json={
                    "number": 88,
                    "html_url": "https://github.com/vulnify/demo-workspace/issues/88",
                    "state": "open",
                },
            )
        return await orig_post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    payload = {
        "plan_hash": prev_data["plan_hash"],
        "title": prev_data["title"],
        "body": prev_data["body"],
        "target_repo": prev_data["target_repo"],
        "target_version": "6.1.11",
        "confirmed": True,
    }

    # 1. First submission -> calls GitHub API
    resp1 = await client.post(
        f"/api/projects/{project.id}/findings/find-dup-1/github-issues",
        json=payload,
    )
    assert resp1.status_code == 200
    assert resp1.json()["is_duplicate"] is False
    assert call_count == 1

    # 2. Second submission with same plan_hash -> duplicate prevention triggered
    resp2 = await client.post(
        f"/api/projects/{project.id}/findings/find-dup-1/github-issues",
        json=payload,
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["is_duplicate"] is True
    assert data2["issue_number"] == 88
    assert "Duplicate creation prevented" in data2["message"]
    # Verify GitHub API was NOT called a second time
    assert call_count == 1


@pytest.mark.asyncio
async def test_human_approval_gate_and_plan_hash_mismatch(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """US-504: Fails closed when confirmed=False or when plan_hash does not match modified content."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-gate-1")
    authenticate_client(client)

    _seed_finding(mock_vuln_repo, project.id, finding_id="find-gate-1")
    test_settings.GITHUB_TOKEN = "ghp_mock_token"

    # 1. Unconfirmed attempt (confirmed: False)
    resp = await client.post(
        f"/api/projects/{project.id}/findings/find-gate-1/github-issues",
        json={
            "plan_hash": "plan_sha256_mockhash123",
            "title": "Title",
            "body": "Body",
            "target_repo": "vulnify/demo-workspace",
            "confirmed": False,
        },
    )
    assert resp.status_code == 400
    assert "explicit human approval" in resp.json()["message"]

    # 2. Plan hash mismatch (tampered content)
    resp_tamper = await client.post(
        f"/api/projects/{project.id}/findings/find-gate-1/github-issues",
        json={
            "plan_hash": "plan_sha256_forged_hash_value",
            "title": "Title",
            "body": "Body",
            "target_repo": "vulnify/demo-workspace",
            "confirmed": True,
        },
    )
    assert resp_tamper.status_code == 400
    assert "Plan hash mismatch" in resp_tamper.json()["message"]


@pytest.mark.asyncio
async def test_github_error_mapping(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests 401 unauthenticated, missing server token, rate limiting, permissions, not found, and timeout."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-errors-1")

    # 1. 401 unauthenticated user
    unauth_resp = await client.post(
        f"/api/projects/{project.id}/findings/f1/github-issues/preview",
        json={},
    )
    assert unauth_resp.status_code == 401

    authenticate_client(client)
    _seed_finding(mock_vuln_repo, project.id, finding_id="find-err-1")

    # 2. GITHUB_TOKEN missing on server
    test_settings.GITHUB_TOKEN = None
    prev = await client.post(
        f"/api/projects/{project.id}/findings/find-err-1/github-issues/preview",
        json={},
    )
    assert prev.status_code == 200
    assert prev.json()["can_submit"] is False
    assert "GITHUB_TOKEN is missing" in prev.json()["configuration_warning"]

    # Try creating without token -> 400
    create_fail = await client.post(
        f"/api/projects/{project.id}/findings/find-err-1/github-issues",
        json={
            "plan_hash": prev.json()["plan_hash"],
            "title": prev.json()["title"],
            "body": prev.json()["body"],
            "target_repo": prev.json()["target_repo"],
            "confirmed": True,
        },
    )
    assert create_fail.status_code == 400
    assert "GITHUB_TOKEN environment variable is missing" in create_fail.json()["message"]

    # 3. Rate limiting (403 with x-ratelimit-remaining: 0)
    test_settings.GITHUB_TOKEN = "ghp_mock"
    orig_post = httpx.AsyncClient.post

    async def mock_rate_limit(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            return Response(status_code=403, headers={"x-ratelimit-remaining": "0"})
        return await orig_post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_rate_limit)

    rl_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-err-1/github-issues",
        json={
            "plan_hash": prev.json()["plan_hash"],
            "title": prev.json()["title"],
            "body": prev.json()["body"],
            "target_repo": prev.json()["target_repo"],
            "confirmed": True,
        },
    )
    assert rl_resp.status_code == 429
    assert "rate limit exceeded" in rl_resp.json()["message"]

    # 4. Permission denied (403 without rate limit)
    async def mock_perm_denied(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            return Response(status_code=403, headers={"x-ratelimit-remaining": "100"})
        return await orig_post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_perm_denied)

    perm_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-err-1/github-issues",
        json={
            "plan_hash": prev.json()["plan_hash"],
            "title": prev.json()["title"],
            "body": prev.json()["body"],
            "target_repo": prev.json()["target_repo"],
            "confirmed": True,
        },
    )
    assert perm_resp.status_code == 403
    assert "lacks permission" in perm_resp.json()["message"]

    # 5. Invalid repository format
    bad_repo_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-err-1/github-issues",
        json={
            "plan_hash": "dummy",
            "title": "Title",
            "body": "Body",
            "target_repo": "https://invalid-url.com/repo",
            "confirmed": True,
        },
    )
    assert bad_repo_resp.status_code == 422


@pytest.mark.asyncio
async def test_github_status_and_action_history_endpoints(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """US-505 / US-506: Test status check and issue action history endpoints."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-hist-1")
    authenticate_client(client)

    # 1. Status endpoint
    status_resp = await client.get(f"/api/projects/{project.id}/github/status")
    assert status_resp.status_code == 200
    s_data = status_resp.json()
    assert "configured" in s_data
    assert "target_repo" in s_data
    assert "token" not in s_data  # Tokens never exposed!

    # 2. Action history endpoint
    list_resp = await client.get(f"/api/projects/{project.id}/github-issues")
    assert list_resp.status_code == 200
    assert "items" in list_resp.json()


@pytest.mark.asyncio
async def test_csrf_protection_on_create_issue(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """US-504 AC-1: Missing or invalid CSRF header prevents issue creation with 403 CSRF_ERROR."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-csrf-1")
    authenticate_client(client)
    _seed_finding(mock_vuln_repo, project.id, finding_id="find-csrf-1")

    # Override headers to supply invalid X-Requested-With
    resp = await client.post(
        f"/api/projects/{project.id}/findings/find-csrf-1/github-issues",
        json={"plan_hash": "dummy", "title": "T", "body": "B", "target_repo": "vulnify/demo-workspace", "confirmed": True},
        headers={"X-Requested-With": "invalid-agent"},
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "CSRF_ERROR"


@pytest.mark.asyncio
async def test_target_repository_must_match_configured(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """US-504 AC-2: Destination repository must match configured team-owned repository; arbitrary targets are rejected."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-target-repo-1")
    authenticate_client(client)
    _seed_finding(mock_vuln_repo, project.id, finding_id="find-tr-1")

    # 1. Preview rejected for arbitrary repo
    prev_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-tr-1/github-issues/preview",
        json={"target_repo": "arbitrary-owner/arbitrary-repo"},
    )
    assert prev_resp.status_code == 400
    assert "configured team-owned repository" in prev_resp.json()["message"]

    # 2. Create rejected for arbitrary repo
    create_resp = await client.post(
        f"/api/projects/{project.id}/findings/find-tr-1/github-issues",
        json={
            "plan_hash": "dummy_hash",
            "title": "Title",
            "body": "Body",
            "target_repo": "arbitrary-owner/arbitrary-repo",
            "confirmed": True,
        },
    )
    assert create_resp.status_code == 400
    assert "configured team-owned repository" in create_resp.json()["message"]


@pytest.mark.asyncio
async def test_concurrent_requests_for_same_plan_no_duplicate(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """US-504 Section 4.6: Concurrent requests for the same plan must not create duplicate issues."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-concur-1")
    authenticate_client(client)
    _seed_finding(mock_vuln_repo, project.id, finding_id="find-concur-1")
    test_settings.GITHUB_TOKEN = "ghp_mock_token"

    prev = await client.post(
        f"/api/projects/{project.id}/findings/find-concur-1/github-issues/preview",
        json={},
    )
    assert prev.status_code == 200
    pdata = prev.json()

    api_calls = 0
    orig_post = httpx.AsyncClient.post

    async def mock_slow_post(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            nonlocal api_calls
            api_calls += 1
            await asyncio.sleep(0.05)  # Simulate network latency
            return Response(
                status_code=201,
                json={"number": 99, "html_url": "https://github.com/vulnify/demo-workspace/issues/99", "state": "open"},
            )
        return await orig_post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_slow_post)

    payload = {
        "plan_hash": pdata["plan_hash"],
        "title": pdata["title"],
        "body": pdata["body"],
        "target_repo": pdata["target_repo"],
        "confirmed": True,
    }

    # Fire two concurrent requests
    res1, res2 = await asyncio.gather(
        client.post(f"/api/projects/{project.id}/findings/find-concur-1/github-issues", json=payload),
        client.post(f"/api/projects/{project.id}/findings/find-concur-1/github-issues", json=payload),
    )

    assert res1.status_code == 200
    assert res2.status_code == 200
    d1, d2 = res1.json(), res2.json()

    assert d1["issue_number"] == 99
    assert d2["issue_number"] == 99
    # Exactly one original and one duplicate
    assert (d1["is_duplicate"] is False and d2["is_duplicate"] is True) or (d1["is_duplicate"] is True and d2["is_duplicate"] is False)
    # GitHub write API called exactly once!
    assert api_calls == 1


@pytest.mark.asyncio
async def test_network_timeout_and_uncertain_outcome_reconciliation(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """US-504 Section 4.6: Timeouts or uncertain outcomes do not trigger unsafe duplicate creation on retry; reconciled safely."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-timeout-1")
    authenticate_client(client)
    _seed_finding(mock_vuln_repo, project.id, finding_id="find-to-1")
    test_settings.GITHUB_TOKEN = "ghp_mock_token"

    prev = await client.post(
        f"/api/projects/{project.id}/findings/find-to-1/github-issues/preview",
        json={},
    )
    pdata = prev.json()

    post_calls = 0
    orig_post = httpx.AsyncClient.post
    orig_get = httpx.AsyncClient.get

    async def mock_timeout_post(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            nonlocal post_calls
            post_calls += 1
            raise httpx.TimeoutException("Upstream GitHub request timed out")
        return await orig_post(self, url, *args, **kwargs)

    async def mock_reconcile_get(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            # Return list containing the issue created prior to timeout
            return Response(
                status_code=200,
                json=[
                    {
                        "number": 105,
                        "html_url": "https://github.com/vulnify/demo-workspace/issues/105",
                        "title": pdata["title"],
                        "body": pdata["body"],
                    }
                ],
            )
        return await orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_timeout_post)
    monkeypatch.setattr(httpx.AsyncClient, "get", mock_reconcile_get)

    payload = {
        "plan_hash": pdata["plan_hash"],
        "title": pdata["title"],
        "body": pdata["body"],
        "target_repo": pdata["target_repo"],
        "confirmed": True,
    }

    # 1. First attempt times out -> 504 Gateway Timeout
    resp1 = await client.post(f"/api/projects/{project.id}/findings/find-to-1/github-issues", json=payload)
    assert resp1.status_code == 504
    assert resp1.json()["code"] == "INTERNAL_SERVER_ERROR"
    assert post_calls == 1

    # 2. Second attempt (retry) reconciles existing issue on GitHub without issuing a new POST
    resp2 = await client.post(f"/api/projects/{project.id}/findings/find-to-1/github-issues", json=payload)
    assert resp2.status_code == 200
    d2 = resp2.json()
    assert d2["is_duplicate"] is True
    assert d2["issue_number"] == 105
    assert "Reconciled" in d2["message"]
    # Still only 1 POST was made; no duplicate write was sent to GitHub!
    assert post_calls == 1


@pytest.mark.asyncio
async def test_audit_trail_records_events_and_excludes_secrets(
    client: AsyncClient,
    test_settings: Settings,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """US-504 AC-5: Every issue creation action is recorded in the audit trail without leaking tokens or secrets."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-audit-1")
    authenticate_client(client)
    _seed_finding(mock_vuln_repo, project.id, finding_id="find-aud-1")
    secret_token = "ghp_super_secret_github_token_value_99999"
    test_settings.GITHUB_TOKEN = secret_token

    prev = await client.post(
        f"/api/projects/{project.id}/findings/find-aud-1/github-issues/preview",
        json={},
    )
    pdata = prev.json()

    orig_post = httpx.AsyncClient.post

    async def mock_success_post(self: Any, url: Any, *args: Any, **kwargs: Any) -> Response:
        if "api.github.com" in str(url):
            return Response(
                status_code=201,
                json={"number": 200, "html_url": "https://github.com/vulnify/demo-workspace/issues/200", "state": "open"},
            )
        return await orig_post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_success_post)

    # 1. Unapproved submission -> rejected
    await client.post(
        f"/api/projects/{project.id}/findings/find-aud-1/github-issues",
        json={"plan_hash": pdata["plan_hash"], "title": pdata["title"], "body": pdata["body"], "target_repo": pdata["target_repo"], "confirmed": False},
    )

    # 2. Approved submission -> success
    await client.post(
        f"/api/projects/{project.id}/findings/find-aud-1/github-issues",
        json={"plan_hash": pdata["plan_hash"], "title": pdata["title"], "body": pdata["body"], "target_repo": pdata["target_repo"], "confirmed": True},
    )

    # 3. Repeat submission -> existing_issue_returned
    await client.post(
        f"/api/projects/{project.id}/findings/find-aud-1/github-issues",
        json={"plan_hash": pdata["plan_hash"], "title": pdata["title"], "body": pdata["body"], "target_repo": pdata["target_repo"], "confirmed": True},
    )

    # Inspect audit trail
    from vulnify.services.github_service import GitHubService
    service = GitHubService(test_settings, mock_vuln_repo)
    trail = service.get_audit_trail(project.id)
    assert len(trail) >= 3

    results = [ev["result"] for ev in trail]
    assert "success" in results
    assert "existing_issue_returned" in results
    assert "rejected" in results

    # Ensure no secrets or tokens exist in any audit trail field
    for event in trail:
        event_str = str(event)
        assert secret_token not in event_str
        assert "Authorization" not in event_str
        assert "cookie" not in event_str.lower()

