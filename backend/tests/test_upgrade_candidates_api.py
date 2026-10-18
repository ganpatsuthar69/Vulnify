"""Tests for US-401 / US-501: Upgrade Candidates API and Evaluation.

Acceptance Criteria verified:
1. Candidates come from the advisory's fixed versions and are labelled recommended, major version or patch only.
2. Compatibility caveats are shown; the tool never claims an upgrade is safe to ship.
3. When no fixed version exists, a clear 'no fix available' state appears.
"""

from typing import Any
from httpx import AsyncClient
import pytest

from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from vulnify.schemas import UpgradeCandidatesResponse, ProjectUpgradeCandidatesResponse
from tests.conftest import ADMIN_USER, authenticate_client


def _seed_test_env(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-upgrades-1",
    project_name: str = "Upgrade Test Project",
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
        description="Test project for upgrade candidates",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _seed_finding(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    project_id: str,
    finding_id: str = "find-upg-001",
    advisory_id: str = "GHSA-upg-test",
    package_name: str = "test-pkg",
    package_version: str = "1.2.0",
    fixed_version: str | None = "1.2.1",
    advisory_fixed_versions: list[str] | None = None,
    path_depth: int = 1,
    service_id: str = "proj-upgrades-1:api-svc",
    service_name: str = "api-svc",
    ecosystem: str = "npm",
) -> dict[str, Any]:
    f_dict = {
        "id": finding_id,
        "project_id": project_id,
        "service_id": service_id,
        "service_name": service_name,
        "advisory_id": advisory_id,
        "advisory_summary": f"Advisory for {package_name}",
        "advisory_details": f"Detailed notes for {advisory_id}",
        "severity": "HIGH",
        "source_url": f"https://github.com/advisories/{advisory_id}",
        "retrieved_at": 1700000000,
        "aliases": ["CVE-2023-99999"],
        "package_version_id": f"{ecosystem}:{package_name}@{package_version}",
        "package_name": package_name,
        "package_version": package_version,
        "ecosystem": ecosystem,
        "match_reason": f"Version {package_version} matches affected range",
        "reason_code": "WITHIN_AFFECTED_RANGE",
        "matched_range": f"< {fixed_version}" if fixed_version else "all versions",
        "fixed_version": fixed_version,
        "advisory_fixed_versions": advisory_fixed_versions or ([fixed_version] if fixed_version else []),
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
        "fixed_versions": advisory_fixed_versions or ([fixed_version] if fixed_version else []),
        "aliases": f_dict["aliases"],
    }
    return f_dict


@pytest.mark.asyncio
async def test_get_upgrade_candidates_unauthenticated(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """AC: Unauthenticated requests return 401 Unauthorized."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    resp = await client.get(
        f"/api/projects/{proj.id}/findings/find-any/upgrade-candidates",
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_upgrade_candidates_project_not_found(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """AC: Unknown project returns 404."""
    _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)
    resp = await client.get(
        "/api/projects/unknown-proj-id/findings/find-any/upgrade-candidates",
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_upgrade_candidates_finding_not_found(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """AC: Unknown finding returns 404."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)
    resp = await client.get(
        f"/api/projects/{proj.id}/findings/non-existent-finding-id/upgrade-candidates",
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp.status_code == 404
    data = resp.json()
    err_text = str(data.get("message") or data.get("detail") or "")
    assert "not found" in err_text.lower()


@pytest.mark.asyncio
async def test_candidate_patch_only_classification_and_caveats(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-1 & AC-2: Patch jump is labelled 'patch only', recommended, and includes caveats and safety disclaimers."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project_id=proj.id,
        finding_id="find-patch-01",
        package_name="lodash",
        package_version="4.17.20",
        fixed_version="4.17.21",
        path_depth=1,
    )

    resp = await client.get(
        f"/api/projects/{proj.id}/findings/find-patch-01/upgrade-candidates",
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["has_fix"] is True
    assert len(data["candidates"]) == 1

    cand = data["candidates"][0]
    assert cand["target_version"] == "4.17.21"
    assert cand["semver_diff"] == "patch"
    assert cand["is_recommended"] is True

    # AC-1: labelled recommended and patch only
    labels = cand["labels"]
    assert any("patch" in l for l in labels)
    assert any("recommended" in l for l in labels)

    # AC-2: Compatibility caveats and safety disclaimer
    caveats = cand["caveats"]
    assert len(caveats) >= 2
    assert any("patch-only" in c.lower() for c in caveats)
    assert any("safe to ship" in c.lower() for c in caveats)

    # Universal disclaimer
    assert "No upgrade is guaranteed safe to ship" in data["safety_disclaimer"]


@pytest.mark.asyncio
async def test_candidate_major_jump_classification_and_caveats(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-1 & AC-2: Major jump is labelled 'major version', warns about breaking changes, and includes safety disclaimer."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project_id=proj.id,
        finding_id="find-major-01",
        package_name="axios",
        package_version="0.21.1",
        fixed_version="1.0.0",
        path_depth=1,
    )

    resp = await client.get(
        f"/api/projects/{proj.id}/findings/find-major-01/upgrade-candidates",
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["has_fix"] is True
    cand = data["candidates"][0]
    assert cand["target_version"] == "1.0.0"
    assert cand["semver_diff"] == "major"
    assert cand["breaking_change_risk"] == "high"

    # AC-1: labelled major version
    labels = cand["labels"]
    assert any("major" in l for l in labels)

    # AC-2: Caveat specifically highlights breaking changes
    caveats = cand["caveats"]
    assert any("breaking" in c.lower() for c in caveats)
    assert any("safe to ship" in c.lower() for c in caveats)


@pytest.mark.asyncio
async def test_multiple_candidates_prefers_patch_as_recommended(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-1: When both patch and major candidates exist, patch is recommended and major is labelled major version."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project_id=proj.id,
        finding_id="find-multi-01",
        package_name="express",
        package_version="4.17.0",
        fixed_version="4.17.3",
        advisory_fixed_versions=["4.17.3", "5.0.0"],
        path_depth=1,
    )

    resp = await client.get(
        f"/api/projects/{proj.id}/findings/find-multi-01/upgrade-candidates",
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["has_fix"] is True
    assert len(data["candidates"]) == 2

    patch_cand = next(c for c in data["candidates"] if c["target_version"] == "4.17.3")
    major_cand = next(c for c in data["candidates"] if c["target_version"] == "5.0.0")

    # Patch is recommended
    assert patch_cand["is_recommended"] is True
    assert any("recommended" in l for l in patch_cand["labels"])
    assert any("patch" in l for l in patch_cand["labels"])

    # Major is NOT recommended
    assert major_cand["is_recommended"] is False
    assert any("major" in l for l in major_cand["labels"])
    assert "recommended" not in major_cand["labels"]


@pytest.mark.asyncio
async def test_no_fix_available_state(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-3: When no fixed version exists, a clear 'no fix available' state appears."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project_id=proj.id,
        finding_id="find-nofix-01",
        package_name="zero-day-lib",
        package_version="1.0.0",
        fixed_version=None,
        advisory_fixed_versions=[],
        path_depth=2,
    )

    resp = await client.get(
        f"/api/projects/{proj.id}/findings/find-nofix-01/upgrade-candidates",
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp.status_code == 200
    data = resp.json()

    # AC-3 mandatory assertions
    assert data["has_fix"] is False
    assert data["candidates"] == []
    assert data["no_fix_message"] is not None
    assert "no fixed version" in data["no_fix_message"].lower()
    assert data["remediation_guidance"] is not None
    assert "workarounds" in data["no_fix_message"].lower() or "mitigations" in data["remediation_guidance"].lower()


@pytest.mark.asyncio
async def test_transitive_dependency_caveat(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-2: Transitive dependencies include caveats explaining parent dependency upgrade requirement."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project_id=proj.id,
        finding_id="find-transitive-01",
        package_name="deep-dep",
        package_version="2.0.0",
        fixed_version="2.0.1",
        path_depth=3,  # transitive
    )

    resp = await client.get(
        f"/api/projects/{proj.id}/findings/find-transitive-01/upgrade-candidates",
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["is_transitive"] is True
    assert data["path_depth"] == 3

    cand = data["candidates"][0]
    caveats_text = " ".join(cand["caveats"]).lower()
    assert "transitive dependency" in caveats_text
    assert "parent" in caveats_text or "overrides" in caveats_text


@pytest.mark.asyncio
async def test_project_wide_upgrade_candidates_endpoint(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Project-wide endpoint GET /api/projects/{project_id}/upgrade-candidates returns aggregated candidates."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project_id=proj.id,
        finding_id="find-p-1",
        package_name="pkg-one",
        package_version="1.0.0",
        fixed_version="1.0.1",
    )
    _seed_finding(
        mock_vuln_repo,
        project_id=proj.id,
        finding_id="find-p-2",
        package_name="pkg-two",
        package_version="2.0.0",
        fixed_version=None,
    )

    resp = await client.get(
        f"/api/projects/{proj.id}/upgrade-candidates",
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["project_id"] == proj.id
    assert data["total_findings"] == 2
    assert data["findings_with_fix"] == 1
    assert data["findings_without_fix"] == 1
    assert len(data["items"]) == 2
    assert "No upgrade is guaranteed safe to ship" in data["safety_disclaimer"]
