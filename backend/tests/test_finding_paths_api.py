"""Tests for US-204: Dependency Path Visualization API (GET /api/projects/{project_id}/findings/{finding_id}/paths)."""

import time
from typing import Any
from httpx import AsyncClient
import pytest

from vulnify.graph.client import get_graph_client
from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import (
    FalkorVulnerabilityRepository,
    InMemoryVulnerabilityRepository,
)
from vulnify.schemas import FindingPathsResponse
from tests.conftest import ADMIN_USER, authenticate_client


def _seed_user_and_project(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-paths-1",
    project_name: str = "Paths Test Project",
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
        description="Test project for dependency paths",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _build_test_finding(
    project_id: str,
    finding_id: str = "find-path-001",
    service_id: str = "proj-paths-1:api-gateway",
    service_name: str = "api-gateway",
    package_name: str = "lodash",
    package_version: str = "4.17.20",
    ecosystem: str = "npm",
    advisory_id: str = "GHSA-test-path",
    path_depth: int = 1,
) -> dict[str, Any]:
    pv_id = f"{ecosystem}:{package_name}@{package_version}"
    return {
        "id": finding_id,
        "project_id": project_id,
        "service_id": service_id,
        "service_name": service_name,
        "advisory_id": advisory_id,
        "advisory_summary": "ReDoS in lodash",
        "advisory_details": "Lodash before 4.17.21 is vulnerable.",
        "severity": "HIGH",
        "source_url": f"https://github.com/advisories/{advisory_id}",
        "retrieved_at": 1700002000,
        "aliases": ["CVE-2020-28500"],
        "package_version_id": pv_id,
        "package_name": package_name,
        "package_version": package_version,
        "ecosystem": ecosystem,
        "match_reason": f"Version {package_version} matched advisory constraint (< 4.17.21).",
        "reason_code": "WITHIN_AFFECTED_RANGE",
        "matched_range": "< 4.17.21",
        "fixed_version": "4.17.21",
        "priority": "High",
        "status": "open",
        "path_depth": path_depth,
        "path_status": "path_found",
    }


@pytest.mark.asyncio
async def test_get_finding_paths_unauthenticated(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """AC-4: Unauthenticated request returns 401 Unauthorized."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    res = await client.get(f"/api/projects/{proj.id}/findings/find-any/paths")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_get_finding_paths_unknown_project(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """Non-existent project returns 404."""
    _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    res = await client.get("/api/projects/unknown-proj/findings/find-001/paths")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_get_finding_paths_unknown_finding_returns_404(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Unknown finding returns 404 with standardized error response."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = []
    res = await client.get(f"/api/projects/{proj.id}/findings/non-existent-finding/paths")
    assert res.status_code == 404
    data = res.json()
    assert data["code"] == "NOT_FOUND"
    assert "not found" in data["message"].lower()


@pytest.mark.asyncio
async def test_get_finding_paths_direct_dependency(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1 & AC2: Direct dependency path has depth 1, is_direct=True, and provenance on every node."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, "find-direct-1", path_depth=1)
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings/{finding['id']}/paths")
    assert res.status_code == 200
    data = res.json()

    # Validate against Pydantic model
    validated = FindingPathsResponse(**data)
    assert validated.has_path is True
    assert validated.total_paths_found == 1
    assert len(validated.paths) == 1

    path = validated.paths[0]
    assert path.depth == 1
    assert path.is_direct is True
    assert len(path.nodes) == 2
    assert len(path.edges) == 1

    # Node 1: Service Root
    node_service = path.nodes[0]
    assert node_service.node_type == "service"
    assert node_service.is_entry_point is True
    assert node_service.is_target is False
    assert node_service.provenance.source_filename is not None
    assert node_service.provenance.classification == "manifest"

    # Node 2: Target Package
    node_target = path.nodes[1]
    assert node_target.node_type == "package"
    assert node_target.is_entry_point is False
    assert node_target.is_target is True
    assert node_target.package_name == "lodash"
    assert node_target.package_version == "4.17.20"

    # Edge: Direct DEPENDS_ON
    edge = path.edges[0]
    assert edge.source_id == node_service.id
    assert edge.target_id == node_target.id
    assert edge.direct is True

    # AC3: Screen-reader text alternative
    assert "Service: api-gateway → lodash@4.17.20" in path.summary_text


@pytest.mark.asyncio
async def test_get_finding_paths_transitive_dependency(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1 & AC2: Transitive dependency path has depth > 1, is_direct=False, and intermediate package nodes."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, "find-trans-1", path_depth=2)
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings/{finding['id']}/paths")
    assert res.status_code == 200
    data = res.json()

    validated = FindingPathsResponse(**data)
    assert validated.has_path is True
    assert len(validated.paths) == 1

    path = validated.paths[0]
    assert path.depth == 2
    assert path.is_direct is False
    assert len(path.nodes) == 3
    assert len(path.edges) == 2

    assert path.nodes[0].node_type == "service"
    assert path.nodes[1].node_type == "package"
    assert path.nodes[1].is_target is False
    assert path.nodes[2].node_type == "package"
    assert path.nodes[2].is_target is True

    # Text alternative
    assert "Service: api-gateway → intermediate-lib@1.0.0 → lodash@4.17.20" in path.summary_text


@pytest.mark.asyncio
async def test_get_finding_paths_multiple_paths_shortest_first(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1: Multiple paths are returned in deterministic shortest-first order."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, "find-multi-1")
    mock_vuln_repo.findings_override[proj.id] = [finding]

    service_id = finding["service_id"]
    target_id = finding["package_version_id"]

    # Provide two paths in reverse order (longer path first, shorter path second)
    path_longer = {
        "id": "path-long",
        "depth": 3,
        "is_direct": False,
        "nodes": [
            {"id": service_id, "node_type": "service", "display_name": "api-gateway", "is_target": False, "is_entry_point": True, "provenance": {"source_filename": "package-lock.json", "content_hash": "hash1", "imported_at": 1700000000, "classification": "manifest", "origin": "stored_graph"}},
            {"id": "pkg-a", "node_type": "package", "display_name": "pkg-a@1.0.0", "is_target": False, "is_entry_point": False, "provenance": {"source_filename": "package-lock.json", "content_hash": "hash1", "imported_at": 1700000000, "classification": "manifest", "origin": "stored_graph"}},
            {"id": "pkg-b", "node_type": "package", "display_name": "pkg-b@1.0.0", "is_target": False, "is_entry_point": False, "provenance": {"source_filename": "package-lock.json", "content_hash": "hash1", "imported_at": 1700000000, "classification": "manifest", "origin": "stored_graph"}},
            {"id": target_id, "node_type": "package", "display_name": "lodash@4.17.20", "is_target": True, "is_entry_point": False, "provenance": {"source_filename": "package-lock.json", "content_hash": "hash1", "imported_at": 1700000000, "classification": "manifest", "origin": "stored_graph"}},
        ],
        "edges": [
            {"id": "e1", "source_id": service_id, "target_id": "pkg-a", "relationship_type": "DEPENDS_ON", "direct": True, "origin": "manifest"},
            {"id": "e2", "source_id": "pkg-a", "target_id": "pkg-b", "relationship_type": "DEPENDS_ON", "direct": False, "origin": "manifest"},
            {"id": "e3", "source_id": "pkg-b", "target_id": target_id, "relationship_type": "DEPENDS_ON", "direct": False, "origin": "manifest"},
        ],
        "summary_text": "Service: api-gateway → pkg-a@1.0.0 → pkg-b@1.0.0 → lodash@4.17.20",
    }
    path_shorter = {
        "id": "path-short",
        "depth": 1,
        "is_direct": True,
        "nodes": [
            {"id": service_id, "node_type": "service", "display_name": "api-gateway", "is_target": False, "is_entry_point": True, "provenance": {"source_filename": "package-lock.json", "content_hash": "hash1", "imported_at": 1700000000, "classification": "manifest", "origin": "stored_graph"}},
            {"id": target_id, "node_type": "package", "display_name": "lodash@4.17.20", "is_target": True, "is_entry_point": False, "provenance": {"source_filename": "package-lock.json", "content_hash": "hash1", "imported_at": 1700000000, "classification": "manifest", "origin": "stored_graph"}},
        ],
        "edges": [
            {"id": "e0", "source_id": service_id, "target_id": target_id, "relationship_type": "DEPENDS_ON", "direct": True, "origin": "manifest"},
        ],
        "summary_text": "Service: api-gateway → lodash@4.17.20",
    }

    mock_vuln_repo.custom_paths[(service_id, target_id)] = [path_longer, path_shorter]

    res = await client.get(f"/api/projects/{proj.id}/findings/{finding['id']}/paths")
    assert res.status_code == 200
    data = res.json()

    paths = data["paths"]
    assert len(paths) == 2
    # Shortest first: depth 1 before depth 3
    assert paths[0]["depth"] == 1
    assert paths[0]["is_direct"] is True
    assert paths[1]["depth"] == 3
    assert paths[1]["is_direct"] is False


def _make_test_node(node_id: str, is_service: bool = False, is_target: bool = False) -> dict[str, Any]:
    return {
        "id": node_id,
        "node_type": "service" if is_service else "package",
        "display_name": node_id,
        "is_target": is_target,
        "is_entry_point": is_service,
        "provenance": {
            "source_filename": "package-lock.json",
            "content_hash": "hash123",
            "imported_at": 1700000000,
            "classification": "manifest",
            "origin": "stored_graph",
        },
    }


@pytest.mark.asyncio
async def test_get_finding_paths_depth_and_limit_bounds(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1: max_depth and limit parameters filter results and set is_truncated properly."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, "find-bounds-1")
    mock_vuln_repo.findings_override[proj.id] = [finding]

    service_id = finding["service_id"]
    target_id = finding["package_version_id"]

    p1 = {
        "id": "p1",
        "depth": 1,
        "is_direct": True,
        "nodes": [_make_test_node(service_id, is_service=True), _make_test_node(target_id, is_target=True)],
        "edges": [{"id": "e1", "source_id": service_id, "target_id": target_id, "relationship_type": "DEPENDS_ON", "direct": True, "origin": "manifest"}],
        "summary_text": "p1",
    }
    p2 = {
        "id": "p2",
        "depth": 2,
        "is_direct": False,
        "nodes": [_make_test_node(service_id, is_service=True), _make_test_node("inter-1"), _make_test_node(target_id, is_target=True)],
        "edges": [
            {"id": "e1", "source_id": service_id, "target_id": "inter-1", "relationship_type": "DEPENDS_ON", "direct": True, "origin": "manifest"},
            {"id": "e2", "source_id": "inter-1", "target_id": target_id, "relationship_type": "DEPENDS_ON", "direct": False, "origin": "manifest"},
        ],
        "summary_text": "p2",
    }
    p3 = {
        "id": "p3",
        "depth": 4,
        "is_direct": False,
        "nodes": [_make_test_node(service_id, is_service=True), _make_test_node("inter-1"), _make_test_node("inter-2"), _make_test_node(target_id, is_target=True)],
        "edges": [
            {"id": "e1", "source_id": service_id, "target_id": "inter-1", "relationship_type": "DEPENDS_ON", "direct": True, "origin": "manifest"},
            {"id": "e2", "source_id": "inter-1", "target_id": "inter-2", "relationship_type": "DEPENDS_ON", "direct": False, "origin": "manifest"},
            {"id": "e3", "source_id": "inter-2", "target_id": target_id, "relationship_type": "DEPENDS_ON", "direct": False, "origin": "manifest"},
        ],
        "summary_text": "p3",
    }

    mock_vuln_repo.custom_paths[(service_id, target_id)] = [p1, p2, p3]

    # Test max_depth=2: p3 (depth 4) should be excluded
    res = await client.get(f"/api/projects/{proj.id}/findings/{finding['id']}/paths?max_depth=2")
    assert res.status_code == 200
    data = res.json()
    assert len(data["paths"]) == 2
    assert all(p["depth"] <= 2 for p in data["paths"])

    # Test limit=1: only 1 path returned, is_truncated=True
    res_lim = await client.get(f"/api/projects/{proj.id}/findings/{finding['id']}/paths?limit=1")
    assert res_lim.status_code == 200
    data_lim = res_lim.json()
    assert len(data_lim["paths"]) == 1
    assert data_lim["is_truncated"] is True


@pytest.mark.asyncio
async def test_get_finding_paths_cycles_and_duplicates_eliminated(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1: Cyclic paths and duplicate paths are eliminated."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, "find-clean-1")
    mock_vuln_repo.findings_override[proj.id] = [finding]

    service_id = finding["service_id"]
    target_id = finding["package_version_id"]

    valid_p = {
        "id": "p-valid",
        "depth": 2,
        "is_direct": False,
        "nodes": [_make_test_node(service_id, is_service=True), _make_test_node("pkg-x"), _make_test_node(target_id, is_target=True)],
        "edges": [
            {"id": "e1", "source_id": service_id, "target_id": "pkg-x", "relationship_type": "DEPENDS_ON", "direct": True, "origin": "manifest"},
            {"id": "e2", "source_id": "pkg-x", "target_id": target_id, "relationship_type": "DEPENDS_ON", "direct": False, "origin": "manifest"},
        ],
        "summary_text": "valid",
    }
    cycle_p = {
        "id": "p-cycle",
        "depth": 3,
        "is_direct": False,
        "nodes": [_make_test_node(service_id, is_service=True), _make_test_node("pkg-x"), _make_test_node(service_id, is_service=True), _make_test_node(target_id, is_target=True)],
        "edges": [],
        "summary_text": "cycle",
    }
    duplicate_p = {
        "id": "p-dup",
        "depth": 2,
        "is_direct": False,
        "nodes": [_make_test_node(service_id, is_service=True), _make_test_node("pkg-x"), _make_test_node(target_id, is_target=True)],
        "edges": [
            {"id": "e1", "source_id": service_id, "target_id": "pkg-x", "relationship_type": "DEPENDS_ON", "direct": True, "origin": "manifest"},
            {"id": "e2", "source_id": "pkg-x", "target_id": target_id, "relationship_type": "DEPENDS_ON", "direct": False, "origin": "manifest"},
        ],
        "summary_text": "valid",
    }

    mock_vuln_repo.custom_paths[(service_id, target_id)] = [valid_p, cycle_p, duplicate_p]

    res = await client.get(f"/api/projects/{proj.id}/findings/{finding['id']}/paths")
    assert res.status_code == 200
    data = res.json()
    assert len(data["paths"]) == 1
    assert data["paths"][0]["id"] == "p-valid"


@pytest.mark.asyncio
async def test_get_finding_paths_no_path_honest_response(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1: No path found returns 200 with has_path=False, paths=[], without claiming safety."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _build_test_finding(proj.id, "find-nopath-1")
    mock_vuln_repo.findings_override[proj.id] = [finding]

    # Explicitly set empty paths for this service + target
    mock_vuln_repo.custom_paths[(finding["service_id"], finding["package_version_id"])] = []

    res = await client.get(f"/api/projects/{proj.id}/findings/{finding['id']}/paths")
    assert res.status_code == 200
    data = res.json()
    assert data["has_path"] is False
    assert data["paths"] == []
    assert data["total_paths_found"] == 0


@pytest.mark.asyncio
async def test_get_finding_paths_validation_error_on_invalid_bounds(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """Invalid query parameter bounds (e.g. limit > 20, max_depth < 1) return 422 Unprocessable Entity."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    # limit > 20
    res = await client.get(f"/api/projects/{proj.id}/findings/find-1/paths?limit=50")
    assert res.status_code == 422

    # max_depth < 1
    res2 = await client.get(f"/api/projects/{proj.id}/findings/find-1/paths?max_depth=0")
    assert res2.status_code == 422


@pytest.mark.asyncio
async def test_falkordb_real_query_execution_and_latency() -> None:
    """AC4 & DoD: Real FalkorDB execution of get_project_finding_paths query under 1 second."""
    client = get_graph_client()
    graph = client.get_graph()
    repo = FalkorVulnerabilityRepository(client=client)

    service_id = "test-real-svc-paths"
    pkg1_id = "npm:test-lib-a@1.0.0"
    pkg2_id = "npm:test-lib-b@2.0.0"

    try:
        # Create small test fixture in FalkorDB
        graph.query(
            """
            CREATE (s:Service {id: $s_id, name: "payment-gateway"})
            CREATE (p1:PackageVersion {id: $p1_id, name: "test-lib-a", version: "1.0.0", ecosystem: "npm", purl: "pkg:npm/test-lib-a@1.0.0"})
            CREATE (p2:PackageVersion {id: $p2_id, name: "test-lib-b", version: "2.0.0", ecosystem: "npm", purl: "pkg:npm/test-lib-b@2.0.0"})
            CREATE (ie:ImportEvent {id: "ie-test-real", filename: "package-lock.json", sha256_hash: "mockhash123", imported_at: 1729000000})
            CREATE (s)-[:IMPORTED_FROM]->(ie)
            CREATE (s)-[:DEPENDS_ON {direct: true, origin: "manifest"}]->(p1)
            CREATE (p1)-[:DEPENDS_ON {direct: false, origin: "manifest"}]->(p2)
            """,
            {"s_id": service_id, "p1_id": pkg1_id, "p2_id": pkg2_id},
        )

        # Measure query latency
        start_time = time.perf_counter()
        paths, is_truncated, total_found = repo.get_finding_dependency_paths(
            project_id="test-proj",
            service_id=service_id,
            package_version_id=pkg2_id,
            max_depth=8,
            limit=5,
        )
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Assert query execution is well below 1 second (1000ms)
        assert elapsed_ms < 1000, f"Query took {elapsed_ms:.2f}ms, exceeding 1000ms SLA"

        # Verify path contents
        assert len(paths) == 1
        path = paths[0]
        assert path["depth"] == 2
        assert path["is_direct"] is False
        assert len(path["nodes"]) == 3
        assert path["nodes"][0]["node_type"] == "service"
        assert path["nodes"][0]["display_name"] == "payment-gateway"
        assert path["nodes"][0]["provenance"]["source_filename"] == "package-lock.json"
        assert path["nodes"][0]["provenance"]["content_hash"] == "mockhash123"
        assert path["nodes"][2]["node_type"] == "package"
        assert path["nodes"][2]["is_target"] is True
        assert path["summary_text"] == "Service: payment-gateway → test-lib-a@1.0.0 → test-lib-b@2.0.0"

    finally:
        # Clean up fixture
        graph.query(
            "MATCH (n) WHERE n.id IN [$s_id, $p1_id, $p2_id, 'ie-test-real'] DETACH DELETE n",
            {"s_id": service_id, "p1_id": pkg1_id, "p2_id": pkg2_id},
        )
