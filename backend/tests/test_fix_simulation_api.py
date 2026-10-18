"""Tests for US-501 / US-502: Fix Simulation API and Graph Overlay Engine.

Acceptance Criteria verified:
1. Runs on a scenario copy or overlay of the graph and shows findings cleared, unchanged, and newly introduced (AC-1).
2. Labels the method as simulated from metadata or verified in a sandbox (AC-2).
3. The scenario never changes the real graph (AC-3).
"""

from typing import Any
from httpx import AsyncClient
import pytest

from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from vulnify.schemas import SimulationResponse, SimulationListResponse
from tests.conftest import ADMIN_USER, authenticate_client


def _seed_test_env(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-sim-1",
    project_name: str = "Simulation Test Project",
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
        description="Test project for fix simulation",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _seed_finding(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    project_id: str,
    finding_id: str = "find-sim-001",
    advisory_id: str = "GHSA-sim-test",
    package_name: str = "express",
    package_version: str = "4.17.1",
    fixed_version: str | None = "4.17.3",
    advisory_fixed_versions: list[str] | None = None,
    path_depth: int = 1,
    service_id: str = "proj-sim-1:web-svc",
    service_name: str = "web-svc",
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
        "aliases": ["CVE-2022-24999"],
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
async def test_simulate_fix_cleared_and_unchanged_delta(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-1: Shows findings cleared, unchanged, and newly introduced."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-sim-delta")
    authenticate_client(client)

    # Seed finding 1 on express 4.17.1 (fixed in 4.17.3)
    _seed_finding(
        mock_vuln_repo,
        project.id,
        finding_id="find-express-1",
        advisory_id="GHSA-express-vuln",
        package_name="express",
        package_version="4.17.1",
        fixed_version="4.17.3",
    )

    # Seed finding 2 on unrelated package lodash 4.17.20 (fixed in 4.17.21)
    _seed_finding(
        mock_vuln_repo,
        project.id,
        finding_id="find-lodash-1",
        advisory_id="GHSA-lodash-vuln",
        package_name="lodash",
        package_version="4.17.20",
        fixed_version="4.17.21",
    )

    payload = {
        "finding_id": "find-express-1",
        "package_name": "express",
        "current_version": "4.17.1",
        "target_version": "4.18.2",
        "ecosystem": "npm",
    }

    resp = await client.post(f"/api/projects/{project.id}/simulations", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # AC-1 assertions:
    assert data["total_findings_cleared"] == 1
    assert data["total_findings_unchanged"] == 1
    assert data["total_findings_introduced"] == 0

    assert len(data["cleared_findings"]) == 1
    cleared = data["cleared_findings"][0]
    assert cleared["finding_id"] == "find-express-1"
    assert cleared["package_name"] == "express"
    assert cleared["status"] == "expected_resolved"
    assert "4.18.2" in cleared["explanation"]
    assert "4.17.3" in cleared["explanation"]

    assert len(data["unchanged_findings"]) == 1
    unchanged = data["unchanged_findings"][0]
    assert unchanged["finding_id"] == "find-lodash-1"
    assert unchanged["package_name"] == "lodash"


@pytest.mark.asyncio
async def test_simulate_fix_method_labeling_and_checklist(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-2: Labels method as simulated from metadata or verified in sandbox and includes honest boundaries."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-sim-method")
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project.id,
        finding_id="find-method-1",
        package_name="axios",
        package_version="0.21.1",
        fixed_version="0.21.2",
    )

    payload = {
        "package_name": "axios",
        "current_version": "0.21.1",
        "target_version": "0.21.4",
        "ecosystem": "npm",
    }

    resp = await client.post(f"/api/projects/{project.id}/simulations", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    # AC-2 assertions:
    assert data["method"] == "simulated_from_metadata"
    assert "in-memory graph overlay" in data["method_description"]
    assert data["is_simulation"] is True

    # Checklist assertions
    checks = {c["name"]: c for c in data["checks_performed"]}
    assert "Advisory Fixed Version Verification" in checks
    assert checks["Advisory Fixed Version Verification"]["status"] == "passed"

    assert "Graph Path Exposure Analysis" in checks
    assert checks["Graph Path Exposure Analysis"]["status"] == "passed"

    assert "Package Manager Lockfile Resolution" in checks
    assert checks["Package Manager Lockfile Resolution"]["status"] == "not_evaluated"

    assert "Runtime Sandbox Execution" in checks
    assert checks["Runtime Sandbox Execution"]["status"] == "not_evaluated"

    # Honest safety disclaimer
    assert "No upgrade is guaranteed safe to ship" in data["safety_disclaimer"]


@pytest.mark.asyncio
async def test_simulate_fix_guarantees_real_graph_not_mutated(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC-3: The scenario never changes the real graph."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-sim-nonmutate")
    authenticate_client(client)

    f_dict = _seed_finding(
        mock_vuln_repo,
        project.id,
        finding_id="find-nomutate-1",
        package_name="tar",
        package_version="6.1.0",
        fixed_version="6.1.9",
    )

    # Snapshot state before simulation
    findings_before = list(mock_vuln_repo.findings_override[project.id])
    assert len(findings_before) == 1
    assert findings_before[0]["status"] == "open"
    assert findings_before[0]["package_version"] == "6.1.0"

    payload = {
        "finding_id": "find-nomutate-1",
        "package_name": "tar",
        "current_version": "6.1.0",
        "target_version": "6.1.11",
        "ecosystem": "npm",
    }

    resp = await client.post(f"/api/projects/{project.id}/simulations", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    # AC-3 explicit field
    assert data["real_graph_mutated"] is False

    # Verify actual repository was NOT mutated
    findings_after = mock_vuln_repo.findings_override[project.id]
    assert len(findings_after) == 1
    assert findings_after[0]["status"] == "open"
    assert findings_after[0]["package_version"] == "6.1.0"
    assert findings_after[0] == findings_before[0]


@pytest.mark.asyncio
async def test_simulate_fix_semver_risk_and_transitive_detection(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Tests SemVer breaking change risk assessment and transitive dependency detection."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-sim-risk")
    authenticate_client(client)

    # Seed transitive finding at depth 3
    _seed_finding(
        mock_vuln_repo,
        project.id,
        finding_id="find-transitive-1",
        package_name="nested-lib",
        package_version="1.0.0",
        fixed_version="2.0.0",
        path_depth=3,
    )

    payload = {
        "finding_id": "find-transitive-1",
        "package_name": "nested-lib",
        "current_version": "1.0.0",
        "target_version": "2.0.0",
        "ecosystem": "npm",
    }

    resp = await client.post(f"/api/projects/{project.id}/simulations", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["is_transitive"] is True
    assert data["path_depth"] == 3
    assert data["breaking_change_risk"] == "high"
    assert any("Major version upgrade" in c for c in data["compatibility_caveats"])
    assert any("Transitive dependency" in c for c in data["compatibility_caveats"])


@pytest.mark.asyncio
async def test_list_and_get_simulation_history(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Tests simulation history recording and retrieval."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-sim-history")
    authenticate_client(client)

    _seed_finding(
        mock_vuln_repo,
        project.id,
        finding_id="find-hist-1",
        package_name="debug",
        package_version="2.6.8",
        fixed_version="2.6.9",
    )

    payload = {
        "finding_id": "find-hist-1",
        "package_name": "debug",
        "current_version": "2.6.8",
        "target_version": "2.6.9",
        "ecosystem": "npm",
    }

    post_resp = await client.post(f"/api/projects/{project.id}/simulations", json=payload)
    assert post_resp.status_code == 200
    sim_id = post_resp.json()["id"]

    # List simulations
    list_resp = await client.get(f"/api/projects/{project.id}/simulations")
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["total"] >= 1
    assert any(item["id"] == sim_id for item in list_data["items"])

    # Get single simulation
    get_resp = await client.get(f"/api/projects/{project.id}/simulations/{sim_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == sim_id


@pytest.mark.asyncio
async def test_simulation_error_handling(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Tests 401 unauthenticated, 404 project not found, 404 finding not found, and 422 validation."""
    project = _seed_test_env(mock_user_repo, mock_project_repo, "proj-sim-err")

    # 1. 401 Unauthenticated
    resp = await client.post(f"/api/projects/{project.id}/simulations", json={
        "package_name": "foo",
        "current_version": "1.0.0",
        "target_version": "1.0.1",
    })
    assert resp.status_code == 401

    authenticate_client(client)

    # 2. 404 Project Not Found
    resp = await client.post("/api/projects/proj-does-not-exist/simulations", json={
        "package_name": "foo",
        "current_version": "1.0.0",
        "target_version": "1.0.1",
    })
    assert resp.status_code == 404

    # 3. 404 Finding Not Found
    resp = await client.post(f"/api/projects/{project.id}/simulations", json={
        "finding_id": "non-existent-finding",
        "package_name": "foo",
        "current_version": "1.0.0",
        "target_version": "1.0.1",
    })
    assert resp.status_code == 404

    # 4. 422 Unprocessable Entity (missing target_version)
    resp = await client.post(f"/api/projects/{project.id}/simulations", json={
        "package_name": "foo",
        "current_version": "1.0.0",
        "target_version": "",
    })
    assert resp.status_code == 422
