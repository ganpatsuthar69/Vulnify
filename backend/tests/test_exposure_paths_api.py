"""Tests for US-205: Architectural Exposure Path & Topology Traversal (R2).

Acceptance Criteria:
AC1: Shows internet, entry service, service calls, and package chain in one unified path.
AC2: The screen and response always say 'architectural exposure, not proof of exploitability'.
AC3: Synthetic edges are visibly flagged; unsupported ecosystems are listed as not analyzed.
"""

from typing import Any
from httpx import AsyncClient
import pytest

from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from vulnify.schemas import ProjectExposurePathsResponse
from tests.conftest import ADMIN_USER, authenticate_client


def _seed_user_and_project(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-exposure-1",
    project_name: str = "Exposure Test Project",
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
        description="Test project for architectural exposure paths",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _build_test_finding(
    project_id: str,
    finding_id: str = "find-exp-001",
    service_id: str = "proj-exposure-1:cart-service",
    service_name: str = "cart-service",
    package_name: str = "redis-parser",
    package_version: str = "3.0.0",
    ecosystem: str = "npm",
    advisory_id: str = "GHSA-redis-parser",
    path_depth: int = 1,
) -> dict[str, Any]:
    pv_id = f"{ecosystem}:{package_name}@{package_version}"
    return {
        "id": finding_id,
        "project_id": project_id,
        "service_id": service_id,
        "service_name": service_name,
        "advisory_id": advisory_id,
        "advisory_summary": "ReDoS vulnerability in redis-parser",
        "advisory_details": "Vulnerable to regex denial of service.",
        "severity": "HIGH",
        "source_url": f"https://github.com/advisories/{advisory_id}",
        "retrieved_at": 1700002000,
        "aliases": ["CVE-2021-99999"],
        "package_version_id": pv_id,
        "package_name": package_name,
        "package_version": package_version,
        "ecosystem": ecosystem,
        "match_reason": f"Version {package_version} matched advisory range.",
        "reason_code": "WITHIN_AFFECTED_RANGE",
        "matched_range": "< 3.0.1",
        "fixed_version": "3.0.1",
        "priority": "High",
        "status": "open",
        "path_depth": path_depth,
        "path_status": "path_found",
    }


# ==============================================================================
# 1. Authorization & Parameter Validation
# ==============================================================================


@pytest.mark.asyncio
async def test_exposure_paths_unauthenticated_returns_401(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """Unauthenticated request is rejected with 401."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    res = await client.get(f"/api/projects/{proj.id}/exposure-paths")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_exposure_paths_nonexistent_project_returns_404(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """Nonexistent project identifier returns 404."""
    _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)
    res = await client.get("/api/projects/proj-does-not-exist/exposure-paths")
    assert res.status_code == 404


# ==============================================================================
# 2. End-to-End Architectural Exposure Traversal (AC1 & AC2)
# ==============================================================================


@pytest.mark.asyncio
async def test_architectural_exposure_path_with_internet_ingress_and_service_calls(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1 & AC2: Traverses Internet -> Entry Service -> Service Call -> Affected Service -> Package Chain."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    # Setup topology: gateway (internet_facing=True) -[CALLS (synthetic)]-> cart-service
    mock_vuln_repo.services[proj.id] = [
        {"id": f"{proj.id}:gateway", "name": "gateway", "internet_facing": True},
        {"id": f"{proj.id}:cart-service", "name": "cart-service", "internet_facing": False},
    ]
    mock_vuln_repo.service_calls[proj.id] = [
        {"source": "gateway", "target": "cart-service", "origin": "synthetic"}
    ]

    finding = _build_test_finding(proj.id)
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/exposure-paths")
    assert res.status_code == 200
    data = res.json()

    # Validate ProjectExposurePathsResponse schema
    ProjectExposurePathsResponse(**data)

    assert data["project_id"] == proj.id
    assert data["has_internet_exposure"] is True
    assert data["topology_status"] == "complete"
    assert len(data["items"]) == 1

    item = data["items"][0]
    assert item["finding_id"] == finding["id"]
    assert item["exposure_status"] == "internet_exposed"
    assert item["has_internet_facing_entry"] is True
    assert item["entry_service_name"] == "gateway"
    assert item["is_entry_service_internet_facing"] is True
    assert item["service_hop_count"] == 1
    assert item["has_synthetic_edges"] is True

    # AC2: Mandatory disclaimer verification
    disclaimer = data["disclaimer"]
    assert "architectural exposure, not proof of exploitability" in disclaimer.lower()
    assert "no path found" in disclaimer.lower()
    assert item["non_exploitability_disclaimer"] == disclaimer

    # AC1: Path node structure verification
    assert len(item["paths"]) >= 1
    p = item["paths"][0]
    node_types = [n["node_type"] for n in p["nodes"]]
    assert node_types[0] == "internet"
    assert node_types[1] == "service"  # gateway
    assert node_types[2] == "service"  # cart-service
    assert node_types[3] == "package"  # redis-parser

    # AC3: Synthetic edge flag verification
    calls_edge = next(e for e in p["edges"] if e["relationship_type"] == "CALLS")
    assert calls_edge["is_synthetic"] is True
    assert calls_edge["origin"] == "synthetic"


@pytest.mark.asyncio
async def test_direct_internet_facing_service_path(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1: Service is itself internet-facing (0 inter-service calls)."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.services[proj.id] = [
        {"id": f"{proj.id}:public-api", "name": "public-api", "internet_facing": True},
    ]
    mock_vuln_repo.service_calls[proj.id] = []

    finding = _build_test_finding(
        proj.id,
        service_id=f"{proj.id}:public-api",
        service_name="public-api",
        package_name="node-forge",
        package_version="0.10.0",
        advisory_id="GHSA-node-forge",
    )
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/exposure-paths")
    assert res.status_code == 200
    data = res.json()

    assert data["has_internet_exposure"] is True
    item = data["items"][0]
    assert item["service_hop_count"] == 0
    assert item["entry_service_name"] == "public-api"
    assert item["has_synthetic_edges"] is False

    p = item["paths"][0]
    assert p["nodes"][0]["node_type"] == "internet"
    assert p["nodes"][1]["display_name"] == "public-api"


# ==============================================================================
# 3. Internal Only & Missing Topology States
# ==============================================================================


@pytest.mark.asyncio
async def test_internal_service_only_no_internet_path(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Internal service without ingress or inbound calls from internet-facing service."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.services[proj.id] = [
        {"id": f"{proj.id}:offline-worker", "name": "offline-worker", "internet_facing": False},
        {"id": f"{proj.id}:db-service", "name": "db-service", "internet_facing": False},
    ]
    mock_vuln_repo.service_calls[proj.id] = [("offline-worker", "db-service")]

    finding = _build_test_finding(
        proj.id,
        service_id=f"{proj.id}:db-service",
        service_name="db-service",
    )
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/exposure-paths")
    assert res.status_code == 200
    data = res.json()

    assert data["has_internet_exposure"] is False
    assert data["topology_status"] == "internal_only"
    item = data["items"][0]
    assert item["exposure_status"] == "internal_only"
    assert item["has_internet_facing_entry"] is False
    assert item["entry_service_id"] is None


@pytest.mark.asyncio
async def test_missing_topology_handled_honestly(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Project with zero call edges reports missing_topology accurately."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.services[proj.id] = [
        {"id": f"{proj.id}:backend", "name": "backend", "internet_facing": None},
    ]
    mock_vuln_repo.service_calls[proj.id] = []

    finding = _build_test_finding(proj.id, service_id=f"{proj.id}:backend", service_name="backend")
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/exposure-paths")
    assert res.status_code == 200
    data = res.json()

    assert data["topology_status"] == "missing_topology"
    assert data["has_internet_exposure"] is False
    assert data["items"][0]["exposure_status"] == "missing_topology"


# ==============================================================================
# 4. Unsupported Ecosystems (AC3)
# ==============================================================================


@pytest.mark.asyncio
async def test_unsupported_ecosystem_listed_as_not_analyzed(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC3: Unsupported ecosystems (e.g. Maven, NuGet) are listed as not analyzed, not safe."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.services[proj.id] = [
        {"id": f"{proj.id}:java-api", "name": "java-api", "internet_facing": True},
    ]
    mock_vuln_repo.service_calls[proj.id] = []

    maven_finding = _build_test_finding(
        proj.id,
        finding_id="find-maven-001",
        service_id=f"{proj.id}:java-api",
        service_name="java-api",
        package_name="org.apache.logging.log4j:log4j-core",
        package_version="2.14.1",
        ecosystem="maven",
        advisory_id="GHSA-jfh8-c2jp-5v3q",
    )
    mock_vuln_repo.findings_override[proj.id] = [maven_finding]

    res = await client.get(f"/api/projects/{proj.id}/exposure-paths")
    assert res.status_code == 200
    data = res.json()

    assert len(data["unsupported_ecosystems"]) == 1
    ue = data["unsupported_ecosystems"][0]
    assert ue["package_name"] == "org.apache.logging.log4j:log4j-core"
    assert ue["ecosystem"] == "maven"
    assert "not supported" in ue["reason"].lower()

    item = data["items"][0]
    assert item["is_ecosystem_supported"] is False


# ==============================================================================
# 5. Cycles and Complex Topologies
# ==============================================================================


@pytest.mark.asyncio
async def test_cyclic_service_calls_handled_safely(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Cyclic service calls (A -> B -> A) do not cause infinite loops or duplicate nodes."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.services[proj.id] = [
        {"id": f"{proj.id}:svc-a", "name": "svc-a", "internet_facing": True},
        {"id": f"{proj.id}:svc-b", "name": "svc-b", "internet_facing": False},
    ]
    # Cyclic calls: A -> B and B -> A
    mock_vuln_repo.service_calls[proj.id] = [
        {"source": "svc-a", "target": "svc-b", "origin": "manifest"},
        {"source": "svc-b", "target": "svc-a", "origin": "manifest"},
    ]

    finding = _build_test_finding(proj.id, service_id=f"{proj.id}:svc-b", service_name="svc-b")
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/exposure-paths")
    assert res.status_code == 200
    data = res.json()

    assert data["has_internet_exposure"] is True
    item = data["items"][0]
    p = item["paths"][0]
    # Verify no duplicate node occurrences
    node_ids = [n["id"] for n in p["nodes"]]
    assert len(node_ids) == len(set(node_ids))


# ==============================================================================
# 6. Single Finding Exposure Paths Endpoint
# ==============================================================================


@pytest.mark.asyncio
async def test_single_finding_exposure_paths_endpoint(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """GET /api/projects/{id}/findings/{id}/exposure-paths returns finding-specific exposure."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.services[proj.id] = [
        {"id": f"{proj.id}:gateway", "name": "gateway", "internet_facing": True},
        {"id": f"{proj.id}:cart-service", "name": "cart-service", "internet_facing": False},
    ]
    mock_vuln_repo.service_calls[proj.id] = [
        {"source": "gateway", "target": "cart-service", "origin": "synthetic"}
    ]

    finding1 = _build_test_finding(proj.id, finding_id="find-1")
    finding2 = _build_test_finding(proj.id, finding_id="find-2", package_name="express")
    mock_vuln_repo.findings_override[proj.id] = [finding1, finding2]

    # Target finding1 explicitly
    res = await client.get(f"/api/projects/{proj.id}/findings/{finding1['id']}/exposure-paths")
    assert res.status_code == 200
    data = res.json()

    assert len(data["items"]) == 1
    assert data["items"][0]["finding_id"] == finding1["id"]

    # Unknown finding returns 404
    bad_res = await client.get(f"/api/projects/{proj.id}/findings/find-nonexistent/exposure-paths")
    assert bad_res.status_code == 404
