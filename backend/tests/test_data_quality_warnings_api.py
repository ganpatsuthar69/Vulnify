"""Tests for US-207: Honest Empty and Warning States.

Verifies:
- AC1: Honest no-path message explaining that absence of a dependency path does not guarantee safety.
- AC2: Data-quality warnings for missing topology, stale advisory data (7-day policy), and partial imports.
- Project and finding-level scoping, authentication, error contracts, and FalkorDB query execution.
"""

from datetime import datetime, timezone
import time
from httpx import AsyncClient
import pytest

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.graph.client import get_graph_client, load_query
from vulnify.graph.job_repository import InMemoryIngestionJobRepository
from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository, UserRecord
from vulnify.graph.vulnerability_repository import (
    InMemoryVulnerabilityRepository,
    PackageAdvisoryPair,
)
from vulnify.models import IngestionJobRecord, JobStatus, JobType
from vulnify.schemas import ProjectDataQualityResponse


def _seed_user_and_project(
    user_repo: InMemoryUserRepository,
    project_repo: InMemoryProjectRepository,
    project_id: str = "proj-dq-1",
    project_name: str = "Data Quality Test Project",
) -> ProjectRecord:
    user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    user = user_repo.get_by_email(ADMIN_USER["email"])
    if user:
        user.id = ADMIN_USER["id"]
        user_repo._users_by_id[ADMIN_USER["id"]] = user

    proj = ProjectRecord(
        id=project_id,
        name=project_name,
        normalized_name=project_name.lower(),
        ecosystem="npm",
        description="US-207 testing project",
        created_at=1700000000,
    )
    project_repo._projects_by_id[proj.id] = proj
    project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _seed_test_finding(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    project_id: str,
    finding_id: str = "find-dq-100",
    service_id: str = "svc-dq-1",
    service_name: str = "auth-service",
    advisory_id: str = "GHSA-dq-test-1",
    retrieved_at: int | None = None,
    path_status: str = "path_found",
    path_depth: int | None = 2,
) -> dict:
    finding = {
        "id": finding_id,
        "project_id": project_id,
        "service_id": service_id,
        "service_name": service_name,
        "advisory_id": advisory_id,
        "advisory_summary": "Prototype pollution vulnerability",
        "advisory_details": "Detailed description of prototype pollution.",
        "severity": "HIGH",
        "source_url": "https://osv.dev/vulnerability/GHSA-dq-test-1",
        "retrieved_at": retrieved_at,
        "aliases": ["CVE-2024-9999"],
        "package_version_id": "npm:lodash@4.17.20",
        "package_name": "lodash",
        "package_version": "4.17.20",
        "ecosystem": "npm",
        "match_reason": "Version 4.17.20 falls within < 4.17.21",
        "reason_code": "SEMVER_RANGE_MATCH",
        "matched_range": "< 4.17.21",
        "fixed_version": "4.17.21",
        "priority": "High",
        "status": "open",
        "path_depth": path_depth,
        "path_status": path_status,
    }
    mock_vuln_repo.findings_override[project_id] = [finding]
    mock_vuln_repo.vulnerabilities_data[advisory_id] = {
        "summary": finding["advisory_summary"],
        "details": finding["advisory_details"],
        "severity": finding["severity"],
        "retrieved_at": retrieved_at,
    }
    return finding


@pytest.mark.asyncio
async def test_data_quality_unauthenticated_returns_401(client: AsyncClient) -> None:
    """AC4 & Security: Unauthenticated request to data-quality endpoint returns 401."""
    res = await client.get("/api/projects/proj-dq-1/data-quality")
    assert res.status_code == 401
    data = res.json()
    assert data["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.asyncio
async def test_data_quality_unknown_project_returns_404(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """AC4 & Security: Request with unknown project ID returns 404."""
    _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    res = await client.get("/api/projects/non-existent-proj/data-quality")
    assert res.status_code == 404
    data = res.json()
    assert data["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_data_quality_clean_project_no_warnings(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """Project with service calls, fresh advisories, and clean jobs returns has_warnings=False."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    now = int(datetime.now(timezone.utc).timestamp())
    # 1. Services with calls
    mock_vuln_repo.services[proj.id] = [
        {"id": "svc-1", "name": "gateway"},
        {"id": "svc-2", "name": "backend"},
    ]
    mock_vuln_repo.service_calls[proj.id] = [("svc-1", "svc-2")]

    # 2. Fresh advisory (retrieved 1 hour ago)
    mock_vuln_repo.package_advisories[proj.id] = [
        PackageAdvisoryPair(
            package_version_id="npm:pkg@1.0.0",
            package_name="pkg",
            package_version="1.0.0",
            ecosystem="npm",
            vulnerability_id="VULN-FRESH",
            affected_ranges="[]",
            fixed_versions=[],
            summary="Fresh vuln",
            severity="LOW",
        )
    ]
    mock_vuln_repo.vulnerabilities_data["VULN-FRESH"] = {
        "summary": "Fresh vuln",
        "retrieved_at": now - 3600,
    }

    # 3. Clean succeeded job
    clean_job = IngestionJobRecord(
        id="job-clean-1",
        project_id=proj.id,
        job_type=JobType.DEPENDENCY_IMPORT,
        status=JobStatus.SUCCEEDED,
        stage="Completed",
        created_at=now - 3600,
        completed_at=now - 3500,
        skipped_items=0,
        failed_items=0,
    )
    mock_job_repo.upsert_job(clean_job)

    res = await client.get(f"/api/projects/{proj.id}/data-quality")
    assert res.status_code == 200
    data = res.json()
    assert data["has_warnings"] is False
    assert data["warning_count"] == 0
    assert len(data["warnings"]) == 0


@pytest.mark.asyncio
async def test_missing_topology_warning(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC2: Detects missing service-to-service topology when services exist without call edges."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    # Services exist, but no inter-service call edges
    mock_vuln_repo.services[proj.id] = [
        {"id": "svc-1", "name": "user-service"},
        {"id": "svc-2", "name": "order-service"},
    ]
    mock_vuln_repo.service_calls[proj.id] = []

    res = await client.get(f"/api/projects/{proj.id}/data-quality")
    assert res.status_code == 200
    data = res.json()
    assert data["has_warnings"] is True

    topo_warn = next((w for w in data["warnings"] if w["code"] == "MISSING_TOPOLOGY"), None)
    assert topo_warn is not None
    assert topo_warn["category"] == "missing_topology"
    assert topo_warn["severity"] == "warning"
    assert "Missing Service Topology" in topo_warn["title"]
    assert "internal service dependencies only" in topo_warn["message"]
    assert topo_warn["details"]["service_count"] == 2
    assert topo_warn["details"]["call_edge_count"] == 0


@pytest.mark.asyncio
async def test_stale_advisory_data_warning(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC2: Detects stale advisory data exceeding the 7-day cutoff."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    now = int(datetime.now(timezone.utc).timestamp())
    # 10 days ago (older than 7 days)
    ten_days_ago = now - (10 * 86400)

    mock_vuln_repo.package_advisories[proj.id] = [
        PackageAdvisoryPair(
            package_version_id="npm:old-lib@1.0.0",
            package_name="old-lib",
            package_version="1.0.0",
            ecosystem="npm",
            vulnerability_id="VULN-STALE",
            affected_ranges="[]",
            fixed_versions=[],
            summary="Stale advisory",
            severity="MEDIUM",
        )
    ]
    mock_vuln_repo.vulnerabilities_data["VULN-STALE"] = {
        "summary": "Stale advisory",
        "retrieved_at": ten_days_ago,
    }

    res = await client.get(f"/api/projects/{proj.id}/data-quality")
    assert res.status_code == 200
    data = res.json()

    stale_warn = next((w for w in data["warnings"] if w["code"] == "STALE_ADVISORY_DATA"), None)
    assert stale_warn is not None
    assert stale_warn["category"] == "stale_advisory_data"
    assert "Stale Advisory Data" in stale_warn["title"]
    assert "7-day freshness policy" in stale_warn["message"]
    assert stale_warn["details"]["threshold_days"] == 7
    assert stale_warn["details"]["age_days"] >= 10


@pytest.mark.asyncio
async def test_fresh_advisory_does_not_trigger_stale_warning(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Fresh advisory (e.g. 2 days old) does not trigger STALE_ADVISORY_DATA."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    now = int(datetime.now(timezone.utc).timestamp())
    two_days_ago = now - (2 * 86400)

    mock_vuln_repo.package_advisories[proj.id] = [
        PackageAdvisoryPair(
            package_version_id="npm:fresh-lib@1.0.0",
            package_name="fresh-lib",
            package_version="1.0.0",
            ecosystem="npm",
            vulnerability_id="VULN-FRESH-2D",
            affected_ranges="[]",
            fixed_versions=[],
            summary="Fresh advisory",
            severity="LOW",
        )
    ]
    mock_vuln_repo.vulnerabilities_data["VULN-FRESH-2D"] = {
        "summary": "Fresh advisory",
        "retrieved_at": two_days_ago,
    }

    res = await client.get(f"/api/projects/{proj.id}/data-quality")
    assert res.status_code == 200
    data = res.json()
    stale_warn = next((w for w in data["warnings"] if w["code"] == "STALE_ADVISORY_DATA"), None)
    assert stale_warn is None


@pytest.mark.asyncio
async def test_unknown_advisory_freshness_warning(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Advisories missing retrieved_at timestamp trigger UNKNOWN_ADVISORY_FRESHNESS."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.package_advisories[proj.id] = [
        PackageAdvisoryPair(
            package_version_id="npm:unknown-fresh@1.0.0",
            package_name="unknown-fresh",
            package_version="1.0.0",
            ecosystem="npm",
            vulnerability_id="VULN-NO-TIMESTAMP",
            affected_ranges="[]",
            fixed_versions=[],
            summary="Missing timestamp advisory",
            severity="HIGH",
        )
    ]
    mock_vuln_repo.vulnerabilities_data["VULN-NO-TIMESTAMP"] = {
        "summary": "Missing timestamp advisory",
        "retrieved_at": None,
    }

    res = await client.get(f"/api/projects/{proj.id}/data-quality")
    assert res.status_code == 200
    data = res.json()

    warn = next((w for w in data["warnings"] if w["code"] == "UNKNOWN_ADVISORY_FRESHNESS"), None)
    assert warn is not None
    assert warn["category"] == "stale_advisory_data"
    assert "Unknown Advisory Freshness" in warn["title"]
    assert "Freshness cannot be verified" in warn["message"]


@pytest.mark.asyncio
async def test_partial_import_warning(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """AC2: Detects incomplete dependency imports ending in partial status or with skipped items."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    now = int(datetime.now(timezone.utc).timestamp())
    partial_job = IngestionJobRecord(
        id="job-partial-99",
        project_id=proj.id,
        service_name="payment-api",
        job_type=JobType.DEPENDENCY_IMPORT,
        status=JobStatus.PARTIAL,
        stage="Partial import completed with warnings",
        created_at=now - 500,
        skipped_items=5,
        failed_items=2,
    )
    mock_job_repo.upsert_job(partial_job)

    res = await client.get(f"/api/projects/{proj.id}/data-quality")
    assert res.status_code == 200
    data = res.json()

    partial_warn = next((w for w in data["warnings"] if w["code"] == "PARTIAL_IMPORT_DETECTED"), None)
    assert partial_warn is not None
    assert partial_warn["category"] == "partial_import"
    assert partial_warn["severity"] == "warning"
    assert partial_warn["resource_id"] == "job-partial-99"
    assert "Incomplete Dependency Ingestion" in partial_warn["title"]
    assert "2 failed, 5 skipped items" in partial_warn["message"]
    assert partial_warn["details"]["skipped_items"] == 5
    assert partial_warn["details"]["failed_items"] == 2


@pytest.mark.asyncio
async def test_clean_import_no_partial_warning(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """Succeeded ingestion job with 0 skipped/failed items does not trigger warning."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    now = int(datetime.now(timezone.utc).timestamp())
    succeeded_job = IngestionJobRecord(
        id="job-success-1",
        project_id=proj.id,
        job_type=JobType.DEPENDENCY_IMPORT,
        status=JobStatus.SUCCEEDED,
        stage="Completed",
        created_at=now - 500,
        skipped_items=0,
        failed_items=0,
    )
    mock_job_repo.upsert_job(succeeded_job)

    res = await client.get(f"/api/projects/{proj.id}/data-quality")
    assert res.status_code == 200
    data = res.json()
    partial_warn = next((w for w in data["warnings"] if w["code"] == "PARTIAL_IMPORT_DETECTED"), None)
    assert partial_warn is None


@pytest.mark.asyncio
async def test_multiple_simultaneous_warnings(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """Project with missing topology, stale advisories, and partial import returns all three."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    now = int(datetime.now(timezone.utc).timestamp())

    # 1. Missing topology
    mock_vuln_repo.services[proj.id] = [{"id": "s1", "name": "api"}]
    mock_vuln_repo.service_calls[proj.id] = []

    # 2. Stale advisory (14 days old)
    mock_vuln_repo.package_advisories[proj.id] = [
        PackageAdvisoryPair(
            package_version_id="npm:pkg@1.0.0",
            package_name="pkg",
            package_version="1.0.0",
            ecosystem="npm",
            vulnerability_id="VULN-OLD",
            affected_ranges="[]",
            fixed_versions=[],
            summary="Old vuln",
            severity="HIGH",
        )
    ]
    mock_vuln_repo.vulnerabilities_data["VULN-OLD"] = {
        "summary": "Old vuln",
        "retrieved_at": now - (14 * 86400),
    }

    # 3. Partial import
    mock_job_repo.upsert_job(
        IngestionJobRecord(
            id="job-multi-partial",
            project_id=proj.id,
            job_type=JobType.DEPENDENCY_IMPORT,
            status=JobStatus.PARTIAL,
            stage="Partial",
            created_at=now - 100,
            skipped_items=3,
            failed_items=1,
        )
    )

    res = await client.get(f"/api/projects/{proj.id}/data-quality")
    assert res.status_code == 200
    data = res.json()

    assert data["has_warnings"] is True
    assert data["warning_count"] >= 3
    codes = {w["code"] for w in data["warnings"]}
    assert "MISSING_TOPOLOGY" in codes
    assert "STALE_ADVISORY_DATA" in codes
    assert "PARTIAL_IMPORT_DETECTED" in codes


@pytest.mark.asyncio
async def test_finding_detail_includes_data_quality_warnings(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1 & AC2: Finding detail includes contextual data quality warnings and honest no-path status."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    now = int(datetime.now(timezone.utc).timestamp())
    # Seed finding with no confirmed path and stale timestamp (12 days old)
    twelve_days_ago = now - (12 * 86400)
    finding = _seed_test_finding(
        mock_vuln_repo,
        proj.id,
        finding_id="find-nopath-detail",
        retrieved_at=twelve_days_ago,
        path_status="no_path_found",
        path_depth=None,
    )

    res = await client.get(f"/api/projects/{proj.id}/findings/{finding['id']}")
    assert res.status_code == 200
    data = res.json()

    assert "warnings" in data
    assert isinstance(data["warnings"], list)
    codes = {w["code"] for w in data["warnings"]}

    # AC1: No path found disclaimer must be present
    assert "NO_PATH_DISCLAIMER" in codes
    no_path_warn = next(w for w in data["warnings"] if w["code"] == "NO_PATH_DISCLAIMER")
    assert "'No path found' does not guarantee safety" in no_path_warn["message"]

    # AC2: Stale advisory warning must be present
    assert "STALE_ADVISORY_DATA" in codes


@pytest.mark.asyncio
async def test_finding_paths_honest_no_path_message_and_warnings(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC1: Bounded path view returns explicit honest no_path_message when no path exists."""
    proj = _seed_user_and_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = _seed_test_finding(
        mock_vuln_repo,
        proj.id,
        finding_id="find-paths-nopath",
        path_status="no_path_found",
        path_depth=None,
    )
    # Ensure custom_paths has 0 paths
    mock_vuln_repo.custom_paths[(finding["service_id"], finding["package_version_id"])] = []

    res = await client.get(f"/api/projects/{proj.id}/findings/{finding['id']}/paths?max_depth=6")
    assert res.status_code == 200
    data = res.json()

    assert data["has_path"] is False
    assert len(data["paths"]) == 0
    assert data["max_depth_applied"] == 6

    # AC1: no_path_message explicitly explains search scope, depth bounds, and non-guarantee of safety
    assert data["no_path_message"] is not None
    assert "'No path found' does not guarantee safety" in data["no_path_message"]
    assert "within the maximum traversal depth of 6 hops" in data["no_path_message"]
    assert finding["package_name"] in data["no_path_message"]

    # Warnings array is included
    assert "warnings" in data
    assert any(w["code"] == "NO_PATH_DISCLAIMER" for w in data["warnings"])


@pytest.mark.asyncio
async def test_falkordb_real_topology_and_freshness_queries() -> None:
    """AC2 & DoD: Real FalkorDB execution of check_project_topology and freshness queries under 1s."""
    client = get_graph_client()
    graph = client.get_graph()

    # Load and execute topology check
    q_topo = load_query("check_project_topology.cypher")
    t0 = time.perf_counter()
    res_topo = graph.query(q_topo, {"project_id": "non-existent-test-proj"})
    latency_topo = time.perf_counter() - t0
    assert latency_topo < 1.0
    assert len(res_topo.result_set) >= 1

    # Load and execute freshness check
    q_fresh = load_query("check_project_advisories_freshness.cypher")
    t0 = time.perf_counter()
    res_fresh = graph.query(q_fresh, {"project_id": "non-existent-test-proj"})
    latency_fresh = time.perf_counter() - t0
    assert latency_fresh < 1.0
    assert len(res_fresh.result_set) >= 1
