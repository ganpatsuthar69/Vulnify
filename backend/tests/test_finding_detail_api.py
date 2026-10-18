"""Tests for US-203: Finding Detail and Evidence API (GET /api/projects/{project_id}/findings/{finding_id})."""

from typing import Any
from httpx import AsyncClient
import pytest

from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from vulnify.schemas import FindingDetailResponse
from tests.conftest import ADMIN_USER, authenticate_client


def _seed_user_and_project(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-detail-1",
    project_name: str = "Detail Test Project",
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
        description="Test project for finding detail",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _build_test_finding(
    project_id: str,
    finding_id: str = "find-detail-001",
    advisory_id: str = "GHSA-test-detail",
    advisory_summary: str = "Test advisory summary",
    advisory_details: str = "Detailed vulnerability notes with line breaks.\nLine 2.\nLine 3.",
    severity: str = "HIGH",
    matched_range: str = "< 2.0.0",
    fixed_version: str = "2.0.0",
    package_name: str = "vulnerable-lib",
    package_version: str = "1.5.0",
    ecosystem: str = "npm",
    match_reason: str = "Version 1.5.0 is within affected range (< 2.0.0) for GHSA-test-detail.",
    source_url: str = "https://github.com/advisories/GHSA-test-detail",
    retrieved_at: int = 1700001000,
    aliases: list[str] | None = None,
    service_id: str = "proj-detail-1:api-svc",
    service_name: str = "api-svc",
    path_depth: int = 1,
    path_status: str = "path_found",
    priority: str = "High",
    status: str = "open",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "project_id": project_id,
        "service_id": service_id,
        "service_name": service_name,
        "advisory_id": advisory_id,
        "advisory_summary": advisory_summary,
        "advisory_details": advisory_details,
        "severity": severity,
        "source_url": source_url,
        "retrieved_at": retrieved_at,
        "aliases": aliases or ["CVE-2023-12345"],
        "package_version_id": f"{ecosystem}:{package_name}@{package_version}",
        "package_name": package_name,
        "package_version": package_version,
        "ecosystem": ecosystem,
        "match_reason": match_reason,
        "reason_code": "WITHIN_AFFECTED_RANGE",
        "matched_range": matched_range,
        "fixed_version": fixed_version,
        "priority": priority,
        "status": status,
        "path_depth": path_depth,
        "path_status": path_status,
    }


@pytest.mark.asyncio
async def test_get_finding_detail_unauthenticated(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """AC-4: Unauthenticated request returns 401 Unauthorized."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    res = await client.get(f"/api/projects/{proj.id}/findings/find-any")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_get_finding_detail_unknown_project(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """AC-3: Non-existent project returns 404."""
    _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    res = await client.get("/api/projects/unknown-proj-999/findings/find-001")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_get_finding_detail_unknown_finding_returns_404(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-3: Non-existent finding ID returns 404 with clear not-found message."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = []

    res = await client.get(f"/api/projects/{proj.id}/findings/non-existent-finding-id")
    assert res.status_code == 404
    data = res.json()
    assert data["code"] == "NOT_FOUND"
    assert "not found" in data["message"].lower()


@pytest.mark.asyncio
async def test_get_finding_detail_project_isolation(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-3: Finding belonging to Project A cannot be accessed from Project B (returns 404)."""
    proj_a = _seed_user_and_project(mock_user_repo, mock_project_repo, "proj-a", "Project A")
    proj_b = ProjectRecord(
        id="proj-b",
        name="Project B",
        normalized_name="project b",
        ecosystem="npm",
        description="Project B description",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj_b.id] = proj_b
    mock_project_repo._projects_by_norm[proj_b.normalized_name] = proj_b

    authenticate_client(client)

    finding_a = _build_test_finding(proj_a.id, "find-a-001", "GHSA-only-in-a")
    mock_vuln_repo.findings_override[proj_a.id] = [finding_a]
    mock_vuln_repo.findings_override[proj_b.id] = []

    # Access under project A succeeds
    res_a = await client.get(f"/api/projects/{proj_a.id}/findings/find-a-001")
    assert res_a.status_code == 200

    # Access under project B fails with 404
    res_b = await client.get(f"/api/projects/{proj_b.id}/findings/find-a-001")
    assert res_b.status_code == 404


@pytest.mark.asyncio
async def test_get_finding_detail_ac1_evidence_fields(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-1: Finding detail returns all required evidence and advisory fields."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(
        project_id=proj.id,
        finding_id="find-ev-123",
        advisory_id="GHSA-ev-123",
        advisory_summary="Vulnerability in lodash prototype pollution",
        advisory_details="Extended details explaining how the vulnerability functions.",
        severity="HIGH",
        matched_range="< 4.17.21",
        fixed_version="4.17.21",
        package_name="lodash",
        package_version="4.17.20",
        ecosystem="npm",
        match_reason="Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-ev-123.",
        source_url="https://github.com/advisories/GHSA-ev-123",
        retrieved_at=1700002000,
        aliases=["CVE-2020-28500", "OSV-2020-123"],
    )
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings/find-ev-123")
    assert res.status_code == 200
    data = res.json()

    # Validate against Pydantic schema
    validated = FindingDetailResponse(**data)
    assert validated.id == "find-ev-123"
    assert validated.advisory_id == "GHSA-ev-123"
    assert validated.advisory_summary == "Vulnerability in lodash prototype pollution"
    assert validated.advisory_details == "Extended details explaining how the vulnerability functions."
    assert validated.severity == "HIGH"
    assert validated.matched_range == "< 4.17.21"
    assert validated.fixed_version == "4.17.21"
    assert validated.package_version == "4.17.20"
    assert validated.package_name == "lodash"
    assert validated.ecosystem == "npm"
    assert validated.match_reason == "Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-ev-123."
    assert validated.source_url == "https://github.com/advisories/GHSA-ev-123"
    assert validated.retrieved_at == 1700002000
    assert validated.aliases == ["CVE-2020-28500", "OSV-2020-123"]


@pytest.mark.asyncio
async def test_get_finding_detail_lookup_by_advisory_id(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Finding detail can also be resolved directly by advisory ID (e.g. GHSA-xxx)."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(
        project_id=proj.id,
        finding_id="find-hash-999",
        advisory_id="GHSA-direct-lookup",
    )
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings/GHSA-direct-lookup")
    assert res.status_code == 200
    data = res.json()
    assert data["advisory_id"] == "GHSA-direct-lookup"
    assert data["id"] == "find-hash-999"


@pytest.mark.asyncio
async def test_get_finding_detail_ac2_safe_plain_text(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-2: Advisory text with HTML or script tags is safely handled and returned as plain text data."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    untrusted_summary = "<script>alert('xss')</script><b>Bold exploit</b>"
    untrusted_details = "An attacker can inject <img src=x onerror=alert(1)> into the DOM."
    finding = _build_test_finding(
        project_id=proj.id,
        finding_id="find-untrusted-01",
        advisory_id="GHSA-untrusted-01",
        advisory_summary=untrusted_summary,
        advisory_details=untrusted_details,
    )
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings/find-untrusted-01")
    assert res.status_code == 200
    data = res.json()

    # Preserved as literal string data without corruption or injection
    assert data["advisory_summary"] == untrusted_summary
    assert data["advisory_details"] == untrusted_details
