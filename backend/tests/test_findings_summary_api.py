"""Tests for US-202: Summary Cards API, counts calculation, reconciliation, and project scoping."""

from typing import Any
from unittest.mock import MagicMock
from httpx import AsyncClient
import pytest

from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from vulnify.schemas import FindingSummaryResponse
from tests.conftest import ADMIN_USER, authenticate_client


def _seed_user_and_project(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-summary-1",
    project_name: str = "Summary Test Project",
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
        description="Test project for summary",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _build_test_finding(
    project_id: str,
    finding_num: int,
    service_id: str | None = None,
    service_name: str = "payment-api",
    advisory_id: str | None = None,
    package_name: str | None = None,
    priority: str = "unknown",
    status: str = "open",
    path_depth: int | None = 1,
    path_status: str = "path_found",
) -> dict[str, Any]:
    svc_id = service_id or f"{project_id}:{service_name}"
    adv_id = advisory_id or f"GHSA-summary-{finding_num:04d}"
    pkg_name = package_name or f"test-package-{finding_num}"
    return {
        "id": f"find-{project_id[:4]}-{svc_id[-4:]}-{adv_id}-{pkg_name}",
        "project_id": project_id,
        "service_id": svc_id,
        "service_name": service_name,
        "advisory_id": adv_id,
        "advisory_summary": f"Summary test advisory {finding_num}",
        "severity": "HIGH",
        "source_url": f"https://github.com/advisories/{adv_id}",
        "retrieved_at": 1700000000,
        "package_version_id": f"npm:{pkg_name}@1.0.0",
        "package_name": pkg_name,
        "package_version": "1.0.0",
        "ecosystem": "npm",
        "match_reason": f"Version 1.0.0 matched advisory range (< 2.0.0) for {adv_id}.",
        "reason_code": "WITHIN_AFFECTED_RANGE",
        "matched_range": "< 2.0.0",
        "fixed_version": "2.0.0",
        "priority": priority,
        "status": status,
        "path_depth": path_depth,
        "path_status": path_status,
    }


@pytest.mark.asyncio
async def test_project_with_no_findings_returns_four_zero_counts(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """1. A project with no findings returns four genuine zero counts."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = []
    res = await client.get(f"/api/projects/{proj.id}/findings/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["project_id"] == proj.id
    assert data["advisory_matches"] == 0
    assert data["findings_with_path"] == 0
    assert data["findings_without_path"] == 0
    assert data["findings_needing_decision"] == 0


@pytest.mark.asyncio
async def test_project_with_multiple_findings_returns_expected_counts(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """2. A project with multiple findings returns expected server-computed counts."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    findings = [
        _build_test_finding(proj.id, 1, path_depth=1, path_status="path_found", status="open"),
        _build_test_finding(proj.id, 2, path_depth=2, path_status="path_found", status="under_investigation"),
        _build_test_finding(proj.id, 3, path_depth=None, path_status="no_path_found", status="affected"),
        _build_test_finding(proj.id, 4, path_depth=None, path_status="no_path_found", status="not_affected"),
        _build_test_finding(proj.id, 5, path_depth=1, path_status="path_found", status="fixed"),
    ]
    mock_vuln_repo.findings_override[proj.id] = findings

    res = await client.get(f"/api/projects/{proj.id}/findings/summary")
    assert res.status_code == 200
    data = res.json()

    assert data["project_id"] == proj.id
    assert data["advisory_matches"] == 5
    assert data["findings_with_path"] == 3  # items 1, 2, 5
    assert data["findings_without_path"] == 2  # items 3, 4
    assert data["findings_needing_decision"] == 2  # items 1 ('open'), 2 ('under_investigation')


@pytest.mark.asyncio
async def test_findings_with_path_and_without_path_add_up_to_total(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """3. Findings with path + findings without path must equal advisory matches."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    findings = [
        _build_test_finding(proj.id, 1, path_depth=1, path_status="path_found"),
        _build_test_finding(proj.id, 2, path_depth=3, path_status="path_found"),
        _build_test_finding(proj.id, 3, path_depth=None, path_status="no_path_found"),
    ]
    mock_vuln_repo.findings_override[proj.id] = findings

    # Check summary endpoint
    res_summary = await client.get(f"/api/projects/{proj.id}/findings/summary")
    assert res_summary.status_code == 200
    summary = res_summary.json()

    # Check findings list endpoint
    res_list = await client.get(f"/api/projects/{proj.id}/findings")
    assert res_list.status_code == 200
    findings_list = res_list.json()

    # Reconciles with list total
    assert summary["advisory_matches"] == findings_list["total"]
    # Reconciles with subcategories
    assert summary["findings_with_path"] + summary["findings_without_path"] == summary["advisory_matches"]


@pytest.mark.asyncio
async def test_findings_needing_decision_semantics(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """4. Only findings requiring a decision ('open', 'under_investigation') are counted."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    findings = [
        _build_test_finding(proj.id, 1, status="open"),
        _build_test_finding(proj.id, 2, status="under_investigation"),
        _build_test_finding(proj.id, 3, status="affected"),  # Decided
        _build_test_finding(proj.id, 4, status="not_affected"),  # Decided
        _build_test_finding(proj.id, 5, status="fixed"),  # Decided
    ]
    mock_vuln_repo.findings_override[proj.id] = findings

    res = await client.get(f"/api/projects/{proj.id}/findings/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["advisory_matches"] == 5
    assert data["findings_needing_decision"] == 2


@pytest.mark.asyncio
async def test_project_isolation_excludes_other_projects(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """5. Counts from another project are strictly excluded."""
    proj_a = _seed_user_and_project(mock_user_repo, mock_project_repo, "proj-a", "Project A")
    proj_b = ProjectRecord(
        id="proj-b",
        name="Project B",
        normalized_name="project b",
        ecosystem="npm",
        description="Project B",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj_b.id] = proj_b
    mock_project_repo._projects_by_norm[proj_b.normalized_name] = proj_b
    authenticate_client(client)

    mock_vuln_repo.findings_override["proj-a"] = [
        _build_test_finding("proj-a", 1, path_depth=1, path_status="path_found", status="open"),
        _build_test_finding("proj-a", 2, path_depth=2, path_status="path_found", status="open"),
    ]
    mock_vuln_repo.findings_override["proj-b"] = [
        _build_test_finding("proj-b", 1, path_depth=None, path_status="no_path_found", status="fixed"),
        _build_test_finding("proj-b", 2, path_depth=None, path_status="no_path_found", status="fixed"),
        _build_test_finding("proj-b", 3, path_depth=None, path_status="no_path_found", status="fixed"),
    ]

    res_a = await client.get(f"/api/projects/{proj_a.id}/findings/summary")
    assert res_a.status_code == 200
    data_a = res_a.json()
    assert data_a["advisory_matches"] == 2
    assert data_a["findings_with_path"] == 2
    assert data_a["findings_without_path"] == 0
    assert data_a["findings_needing_decision"] == 2

    res_b = await client.get(f"/api/projects/{proj_b.id}/findings/summary")
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert data_b["advisory_matches"] == 3
    assert data_b["findings_with_path"] == 0
    assert data_b["findings_without_path"] == 3
    assert data_b["findings_needing_decision"] == 0


@pytest.mark.asyncio
async def test_unauthenticated_request_returns_401(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """6. Unauthenticated requests to summary endpoint return 401."""
    proj = ProjectRecord(
        id="proj-auth-test",
        name="Auth Test",
        normalized_name="auth test",
        ecosystem="npm",
        description="Auth Test",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj

    res = await client.get(f"/api/projects/{proj.id}/findings/summary")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_missing_project_returns_404(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """7. Requests for a non-existent project return 404."""
    _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    res = await client.get("/api/projects/non-existent-project-id/findings/summary")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_summary_filter_awareness_reconciles_with_list(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """8. Active filters apply consistently to both summary counts and findings list."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    findings = [
        _build_test_finding(proj.id, 1, service_name="auth-api", priority="High", status="open", path_depth=1),
        _build_test_finding(proj.id, 2, service_name="auth-api", priority="Low", status="open", path_depth=1),
        _build_test_finding(proj.id, 3, service_name="payment-api", priority="High", status="fixed", path_depth=2),
    ]
    mock_vuln_repo.findings_override[proj.id] = findings

    # Filter by service_id = auth-api
    auth_svc_id = f"{proj.id}:auth-api"
    res_summary = await client.get(f"/api/projects/{proj.id}/findings/summary?service_id={auth_svc_id}")
    assert res_summary.status_code == 200
    summary_auth = res_summary.json()

    res_list = await client.get(f"/api/projects/{proj.id}/findings?service_id={auth_svc_id}")
    assert res_list.status_code == 200
    list_auth = res_list.json()

    assert summary_auth["advisory_matches"] == 2
    assert summary_auth["advisory_matches"] == list_auth["total"]
    assert summary_auth["findings_with_path"] == 2
    assert summary_auth["findings_needing_decision"] == 2

    # Filter by priority = High
    res_summary_high = await client.get(f"/api/projects/{proj.id}/findings/summary?priority=High")
    assert res_summary_high.status_code == 200
    summary_high = res_summary_high.json()

    res_list_high = await client.get(f"/api/projects/{proj.id}/findings?priority=High")
    assert res_list_high.status_code == 200
    list_high = res_list_high.json()

    assert summary_high["advisory_matches"] == 2
    assert summary_high["advisory_matches"] == list_high["total"]
    assert summary_high["findings_needing_decision"] == 1  # item 1 is open, item 3 is fixed


@pytest.mark.asyncio
async def test_database_failure_returns_500_not_fake_zeros(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """9. Database query failures produce 500 error rather than fake zero counts."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    # Force repo failure
    mock_vuln_repo.get_project_findings_summary = MagicMock(side_effect=RuntimeError("FalkorDB connection timeout"))

    res = await client.get(f"/api/projects/{proj.id}/findings/summary")
    assert res.status_code == 500
    data = res.json()
    assert "message" in data or "code" in data


@pytest.mark.asyncio
async def test_response_conforms_to_pydantic_schema(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """10. Response contract matches FindingSummaryResponse Pydantic schema strictly."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [
        _build_test_finding(proj.id, 1, path_depth=1, path_status="path_found", status="open"),
    ]

    res = await client.get(f"/api/projects/{proj.id}/findings/summary")
    assert res.status_code == 200
    data = res.json()

    # Validates with Pydantic model
    validated = FindingSummaryResponse(**data)
    assert validated.project_id == proj.id
    assert validated.advisory_matches == 1
    assert validated.findings_with_path == 1
    assert validated.findings_without_path == 0
    assert validated.findings_needing_decision == 1
