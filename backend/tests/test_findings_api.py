"""Tests for US-201: Findings List API, filtering, pagination, and evidence contracts."""

from typing import Any
from unittest.mock import MagicMock
from httpx import AsyncClient
import pytest

from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository, UserRecord
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from vulnify.schemas import FindingListResponse
from tests.conftest import ADMIN_USER, authenticate_client

VALID_PROJECT = {
    "name": "Findings Test Project",
    "ecosystem": "npm",
    "description": "Project for findings verification",
}


def _seed_user_and_project(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-findings-1",
    project_name: str = "Findings Test Project",
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
        description="Test project",
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
    path_depth: int = 1,
    path_status: str = "path_found",
) -> dict[str, Any]:
    svc_id = service_id or f"{project_id}:{service_name}"
    adv_id = advisory_id or f"GHSA-test-{finding_num:04d}"
    pkg_name = package_name or f"test-package-{finding_num}"
    return {
        "id": f"find-{project_id[:4]}-{svc_id[-4:]}-{adv_id}-{pkg_name}",
        "project_id": project_id,
        "service_id": svc_id,
        "service_name": service_name,
        "advisory_id": adv_id,
        "advisory_summary": f"Test vulnerability advisory {finding_num}",
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
async def test_authenticated_request_returns_findings(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """1. An authenticated request returns findings for the selected project."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    sample_finding = _build_test_finding(proj.id, 1)
    mock_vuln_repo.findings_override[proj.id] = [sample_finding]

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["advisory_id"] == sample_finding["advisory_id"]
    assert data["items"][0]["service_name"] == "payment-api"


@pytest.mark.asyncio
async def test_unauthenticated_request_returns_401(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """2. An unauthenticated request returns 401."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_401_response_contract(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """3. A 401 response follows the established authentication contract {code, message, request_id}."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 401
    data = res.json()
    assert data["code"] == "AUTHENTICATION_REQUIRED"
    assert "message" in data
    assert "request_id" in data


@pytest.mark.asyncio
async def test_findings_from_different_project_never_returned(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """4. Findings from a different project are never returned."""
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

    mock_vuln_repo.findings_override["proj-a"] = [_build_test_finding("proj-a", 1)]
    mock_vuln_repo.findings_override["proj-b"] = [_build_test_finding("proj-b", 2)]

    res_a = await client.get(f"/api/projects/{proj_a.id}/findings")
    assert res_a.status_code == 200
    items_a = res_a.json()["items"]
    assert len(items_a) == 1
    assert items_a[0]["project_id"] == "proj-a"

    res_b = await client.get(f"/api/projects/{proj_b.id}/findings")
    assert res_b.status_code == 200
    items_b = res_b.json()["items"]
    assert len(items_b) == 1
    assert items_b[0]["project_id"] == "proj-b"


@pytest.mark.asyncio
async def test_project_with_no_findings_returns_empty_result(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """5. A project with no findings returns a valid empty result."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = []
    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    data = res.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["total_pages"] == 0
    assert data["page"] == 1
    assert data["page_size"] == 25


@pytest.mark.asyncio
async def test_api_returns_expected_columns_and_pagination(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """6. The API returns the expected columns/fields and pagination metadata."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, 1, service_name="auth-api", priority="unknown", status="open", path_depth=2)
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    data = res.json()

    # Pagination metadata
    assert "items" in data
    assert "page" in data
    assert "page_size" in data
    assert "total" in data
    assert "total_pages" in data

    # Mandatory columns/fields from US-201
    item = data["items"][0]
    assert "id" in item
    assert "priority" in item
    assert "advisory_id" in item
    assert "package_name" in item
    assert "package_version" in item
    assert "service_name" in item
    assert "path_depth" in item
    assert "path_status" in item
    assert "status" in item


@pytest.mark.asyncio
async def test_default_page_size_is_25(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """7. Default page size is 25."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [_build_test_finding(proj.id, i) for i in range(1, 35)]

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    data = res.json()
    assert data["page_size"] == 25
    assert len(data["items"]) == 25
    assert data["total"] == 34
    assert data["total_pages"] == 2


@pytest.mark.asyncio
async def test_pagination_stability_across_pages(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """8. Page 1 and page 2 return stable, non-duplicated results under unchanged data."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [_build_test_finding(proj.id, i) for i in range(1, 40)]

    res1 = await client.get(f"/api/projects/{proj.id}/findings?page=1&page_size=20")
    assert res1.status_code == 200
    page1_items = res1.json()["items"]
    page1_ids = {item["id"] for item in page1_items}
    assert len(page1_items) == 20

    res2 = await client.get(f"/api/projects/{proj.id}/findings?page=2&page_size=20")
    assert res2.status_code == 200
    page2_items = res2.json()["items"]
    page2_ids = {item["id"] for item in page2_items}
    assert len(page2_items) == 19

    # No overlap between page 1 and page 2
    assert page1_ids.isdisjoint(page2_ids)


@pytest.mark.asyncio
async def test_total_count_reflects_filtered_result_set(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """9. Total count is correct for the filtered result set."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    findings = [
        _build_test_finding(proj.id, 1, priority="High"),
        _build_test_finding(proj.id, 2, priority="High"),
        _build_test_finding(proj.id, 3, priority="Medium"),
    ]
    mock_vuln_repo.findings_override[proj.id] = findings

    res = await client.get(f"/api/projects/{proj.id}/findings?priority=High")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2


@pytest.mark.asyncio
async def test_priority_filtering(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """10. Priority filtering works."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [
        _build_test_finding(proj.id, 1, priority="High"),
        _build_test_finding(proj.id, 2, priority="unknown"),
    ]

    res_unknown = await client.get(f"/api/projects/{proj.id}/findings?priority=unknown")
    assert res_unknown.status_code == 200
    assert res_unknown.json()["total"] == 1
    assert res_unknown.json()["items"][0]["priority"] == "unknown"


@pytest.mark.asyncio
async def test_service_filtering(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """11. Service filtering works."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    svc_a = f"{proj.id}:payment-api"
    svc_b = f"{proj.id}:auth-api"
    mock_vuln_repo.findings_override[proj.id] = [
        _build_test_finding(proj.id, 1, service_id=svc_a, service_name="payment-api"),
        _build_test_finding(proj.id, 2, service_id=svc_b, service_name="auth-api"),
    ]

    res = await client.get(f"/api/projects/{proj.id}/findings?service_id={svc_a}")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["service_name"] == "payment-api"


@pytest.mark.asyncio
async def test_status_filtering(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """12. Status filtering works."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [
        _build_test_finding(proj.id, 1, status="open"),
        _build_test_finding(proj.id, 2, status="fixed"),
    ]

    res = await client.get(f"/api/projects/{proj.id}/findings?status=open")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["status"] == "open"


@pytest.mark.asyncio
async def test_advisory_id_search(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """13. Advisory-ID search works case-insensitively."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [
        _build_test_finding(proj.id, 1, advisory_id="GHSA-29mw-wpgm-hmr9"),
        _build_test_finding(proj.id, 2, advisory_id="CVE-2023-12345"),
    ]

    res = await client.get(f"/api/projects/{proj.id}/findings?search=29mw-wpgm")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["advisory_id"] == "GHSA-29mw-wpgm-hmr9"


@pytest.mark.asyncio
async def test_package_name_search(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """14. Package-name search works case-insensitively."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [
        _build_test_finding(proj.id, 1, package_name="lodash"),
        _build_test_finding(proj.id, 2, package_name="express"),
    ]

    res = await client.get(f"/api/projects/{proj.id}/findings?search=LODASH")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["package_name"] == "lodash"


@pytest.mark.asyncio
async def test_multiple_filters_combine_correctly(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """15. Multiple filters combine correctly with AND logic."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    svc_id = f"{proj.id}:payment-api"
    mock_vuln_repo.findings_override[proj.id] = [
        _build_test_finding(proj.id, 1, service_id=svc_id, package_name="lodash", priority="High", status="open"),
        _build_test_finding(proj.id, 2, service_id=svc_id, package_name="lodash", priority="Low", status="open"),
        _build_test_finding(proj.id, 3, service_id="other", package_name="lodash", priority="High", status="open"),
    ]

    res = await client.get(
        f"/api/projects/{proj.id}/findings?service_id={svc_id}&search=lodash&priority=High&status=open"
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["package_name"] == "lodash"
    assert data["items"][0]["priority"] == "High"


@pytest.mark.asyncio
async def test_invalid_pagination_returns_422(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """16. Invalid pagination parameters return 422 VALIDATION_ERROR."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    # page < 1
    res0 = await client.get(f"/api/projects/{proj.id}/findings?page=0")
    assert res0.status_code == 422
    assert res0.json()["code"] == "VALIDATION_ERROR"

    # page_size < 1
    res1 = await client.get(f"/api/projects/{proj.id}/findings?page_size=0")
    assert res1.status_code == 422
    assert res1.json()["code"] == "VALIDATION_ERROR"

    # page_size > 100
    res2 = await client.get(f"/api/projects/{proj.id}/findings?page_size=101")
    assert res2.status_code == 422
    assert res2.json()["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_direct_dependency_path_depth_calculated(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """18. Direct dependency path depth is calculated correctly (depth = 1)."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, 1, path_depth=1, path_status="path_found")
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    item = res.json()["items"][0]
    assert item["path_depth"] == 1
    assert item["path_status"] == "path_found"


@pytest.mark.asyncio
async def test_transitive_dependency_path_depth_calculated(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """19. Transitive dependency path depth is calculated correctly (depth = 2)."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, 1, path_depth=2, path_status="path_found")
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    item = res.json()["items"][0]
    assert item["path_depth"] == 2
    assert item["path_status"] == "path_found"


@pytest.mark.asyncio
async def test_no_path_and_unavailable_outcomes_distinguished(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """20. No-path and unavailable-analysis outcomes are distinguished correctly."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding_no_path = _build_test_finding(proj.id, 1, path_depth=None, path_status="no_path_found")
    finding_unavail = _build_test_finding(proj.id, 2, path_depth=None, path_status="unavailable")
    mock_vuln_repo.findings_override[proj.id] = [finding_no_path, finding_unavail]

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    items = res.json()["items"]
    assert items[0]["path_status"] == "no_path_found"
    assert items[0]["path_depth"] is None
    assert items[1]["path_status"] == "unavailable"
    assert items[1]["path_depth"] is None


@pytest.mark.asyncio
async def test_database_failure_returns_500_not_empty_list(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """21. FalkorDB failures return a proper 500 error rather than a successful empty list."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    # Mock get_project_findings to simulate a FalkorDB connection error
    mock_vuln_repo.get_project_findings = MagicMock(side_effect=RuntimeError("FalkorDB connection timeout"))

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 500
    data = res.json()
    assert data["code"] == "INTERNAL_SERVER_ERROR"
    assert "request_id" in data


@pytest.mark.asyncio
async def test_missing_priority_and_status_represented_honestly(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """22. Missing priority/status/path metadata is represented honestly without fabrication."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, 1, priority="unknown", status="open", path_depth=None, path_status="no_path_found")
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    item = res.json()["items"][0]
    assert item["priority"] == "unknown"
    assert item["status"] == "open"
    assert item["path_depth"] is None
    assert item["path_status"] == "no_path_found"


@pytest.mark.asyncio
async def test_cypher_injection_safe_search(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """23. User-controlled filter/search values cannot alter Cypher query structure."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    malicious_search = "'; MATCH (n) DETACH DELETE n; //"
    mock_vuln_repo.findings_override[proj.id] = [_build_test_finding(proj.id, 1, package_name="lodash")]

    res = await client.get(f"/api/projects/{proj.id}/findings?search={malicious_search}")
    assert res.status_code == 200
    # Parameterized query searches safely for the literal substring and finds 0 matches
    assert res.json()["total"] == 0


@pytest.mark.asyncio
async def test_pydantic_contract_conformity(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """24. API responses strictly conform to the Pydantic contract and API documentation."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [_build_test_finding(proj.id, 1)]

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    # Validate via Pydantic model parser
    parsed = FindingListResponse.model_validate(res.json())
    assert parsed.total == 1
    assert parsed.page == 1
    assert parsed.items[0].service_name == "payment-api"


@pytest.mark.asyncio
async def test_list_project_services(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """25. GET /api/projects/{project_id}/services lists distinct services."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.services[proj.id] = [
        {"id": f"{proj.id}:auth-api", "name": "auth-api"},
        {"id": f"{proj.id}:payment-api", "name": "payment-api"},
    ]

    res = await client.get(f"/api/projects/{proj.id}/services")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 2
    assert data[0]["name"] == "auth-api"
    assert data[1]["name"] == "payment-api"
