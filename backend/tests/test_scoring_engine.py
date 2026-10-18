"""Tests for Vulnify Deterministic Scoring Engine and Priority Ranking (US-301).

Acceptance Criteria:
- AC1: Documented, deterministic rules in docs/scoring.md (Highest, High, Medium, Low plus tie-breakers).
- AC2: Every finding shows its band and the reasons; missing signals show as unknown, not zero.
- AC3: Unit tests cover each band; identical input produces identical output; scoring version stored with each result.
"""

from typing import Any
import pytest
from httpx import AsyncClient

from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from vulnify.scoring.engine import (
    SCORING_VERSION,
    PriorityBand,
    ScoringResult,
    finding_sort_key,
    normalize_path_status,
    normalize_severity,
    score_finding,
)
from tests.conftest import ADMIN_USER, authenticate_client


# =====================================================================
# Unit Tests: Priority Bands (AC1 & AC3)
# =====================================================================

def test_scoring_version_is_v1() -> None:
    """AC3: Scoring engine reports semantic version v1.0.0."""
    assert SCORING_VERSION == "v1.0.0"
    res = score_finding(severity="CRITICAL", path_status="path_found")
    assert res.scoring_version == "v1.0.0"


def test_band_highest_assigned_for_critical_with_confirmed_path() -> None:
    """AC1 & AC3: Critical severity with confirmed reachable path yields 'Highest'."""
    res = score_finding(
        severity="CRITICAL",
        match_status="affected",
        path_status="path_found",
        path_depth=1,
        fixed_version="2.0.0",
    )
    assert res.priority == PriorityBand.HIGHEST.value
    assert "SEVERITY_CRITICAL" in res.reason_codes
    assert "PATH_DIRECT_REACHABLE" in res.reason_codes
    assert "FIX_VERSION_AVAILABLE" in res.reason_codes
    assert any("Critical" in r for r in res.reasons)
    assert any("Direct dependency" in r for r in res.reasons)


def test_band_high_assigned_for_high_with_confirmed_path() -> None:
    """AC1 & AC3: High severity with confirmed reachable path yields 'High'."""
    res = score_finding(
        severity="HIGH",
        match_status="affected",
        path_status="path_found",
        path_depth=3,
        fixed_version="1.5.0",
    )
    assert res.priority == PriorityBand.HIGH.value
    assert "SEVERITY_HIGH" in res.reason_codes
    assert "PATH_TRANSITIVE_REACHABLE" in res.reason_codes
    assert any("High" in r for r in res.reasons)
    assert any("Transitive dependency" in r and "3 hops" in r for r in res.reasons)


def test_band_medium_assigned_for_moderate_severity_with_path() -> None:
    """AC1 & AC3: Moderate severity with confirmed reachable path yields 'Medium'."""
    res = score_finding(
        severity="MODERATE",
        match_status="affected",
        path_status="path_found",
        path_depth=2,
    )
    assert res.priority == PriorityBand.MEDIUM.value
    assert "SEVERITY_MEDIUM" in res.reason_codes


def test_band_medium_assigned_for_critical_advisory_without_path() -> None:
    """AC1 & AC3: Critical severity advisory without dependency path yields 'Medium'."""
    res = score_finding(
        severity="CRITICAL",
        match_status="affected",
        path_status="no_path_found",
        path_depth=None,
    )
    assert res.priority == PriorityBand.MEDIUM.value
    assert "SEVERITY_CRITICAL" in res.reason_codes
    assert "PATH_NOT_FOUND" in res.reason_codes
    # Reason disclaimer: absence of path does not guarantee safety
    assert any("does not guarantee absence of risk" in r for r in res.reasons)


def test_band_medium_assigned_for_high_advisory_without_path() -> None:
    """AC1 & AC3: High severity advisory without dependency path yields 'Medium'."""
    res = score_finding(
        severity="HIGH",
        match_status="affected",
        path_status="no_path_found",
        path_depth=None,
    )
    assert res.priority == PriorityBand.MEDIUM.value
    assert "SEVERITY_HIGH" in res.reason_codes
    assert "PATH_NOT_FOUND" in res.reason_codes


def test_band_low_assigned_for_low_severity_without_path() -> None:
    """AC1 & AC3: Low severity advisory with no dependency path yields 'Low'."""
    res = score_finding(
        severity="LOW",
        match_status="affected",
        path_status="no_path_found",
        path_depth=None,
    )
    assert res.priority == PriorityBand.LOW.value
    assert "SEVERITY_LOW" in res.reason_codes
    assert "PATH_NOT_FOUND" in res.reason_codes


def test_band_low_assigned_for_triage_resolved_status() -> None:
    """AC1 & AC3: Triage status 'fixed' or 'not_affected' yields 'Low' regardless of severity."""
    res_fixed = score_finding(
        severity="CRITICAL",
        match_status="affected",
        path_status="path_found",
        triage_status="fixed",
    )
    assert res_fixed.priority == PriorityBand.LOW.value
    assert "TRIAGE_STATUS_RESOLVED" in res_fixed.reason_codes

    res_not_aff = score_finding(
        severity="CRITICAL",
        match_status="not_affected",
        path_status="path_found",
    )
    assert res_not_aff.priority == PriorityBand.LOW.value
    assert "MATCH_STATUS_NOT_AFFECTED" in res_not_aff.reason_codes


# =====================================================================
# Unit Tests: Missing Signals Handling (AC2)
# =====================================================================

def test_missing_severity_treated_as_unknown_not_zero() -> None:
    """AC2: Missing severity is treated as unknown, never 0 or low risk."""
    res = score_finding(
        severity=None,
        match_status="affected",
        path_status="path_found",
        path_depth=1,
    )
    assert res.priority == PriorityBand.MEDIUM.value
    assert "SEVERITY_UNKNOWN" in res.reason_codes
    assert any("caution, not zero risk" in r for r in res.reasons)
    assert res.signals["severity"] == "unknown"


def test_missing_path_status_treated_as_unknown_not_safe() -> None:
    """AC2: Unavailable or missing dependency path is treated as unknown, not safe."""
    res = score_finding(
        severity="CRITICAL",
        match_status="affected",
        path_status=None,
        path_depth=None,
    )
    assert res.priority == PriorityBand.MEDIUM.value
    assert "PATH_UNKNOWN" in res.reason_codes
    assert any("not assumed safe" in r for r in res.reasons)
    assert res.signals["path_status"] == "unavailable"


def test_missing_fixed_version_reported_transparently() -> None:
    """AC2: Missing fixed version states remediation target is unknown."""
    res = score_finding(
        severity="HIGH",
        match_status="affected",
        path_status="path_found",
        fixed_version=None,
    )
    assert "FIX_VERSION_UNKNOWN" in res.reason_codes
    assert any("Remediation target unknown" in r for r in res.reasons)


# =====================================================================
# Unit Tests: Determinism (AC3)
# =====================================================================

def test_identical_inputs_produce_identical_results_determinism() -> None:
    """AC3: 100 consecutive invocations with identical inputs produce identical output."""
    baseline = score_finding(
        severity="CRITICAL",
        match_status="affected",
        path_status="path_found",
        path_depth=1,
        fixed_version="3.0.0",
        triage_status="open",
    )

    for _ in range(100):
        run = score_finding(
            severity="CRITICAL",
            match_status="affected",
            path_status="path_found",
            path_depth=1,
            fixed_version="3.0.0",
            triage_status="open",
        )
        assert run.priority == baseline.priority
        assert run.reasons == baseline.reasons
        assert run.reason_codes == baseline.reason_codes
        assert run.scoring_version == baseline.scoring_version


# =====================================================================
# Unit Tests: Deterministic Tie-Breakers (docs/scoring.md Section 4)
# =====================================================================

def test_tie_breakers_order_by_band_weight() -> None:
    """Tie-breaker 1: Highest > High > Medium > Low > unknown."""
    f_highest = {"id": "1", "priority": "Highest", "severity": "CRITICAL", "advisory_id": "GHSA-1"}
    f_high = {"id": "2", "priority": "High", "severity": "HIGH", "advisory_id": "GHSA-2"}
    f_medium = {"id": "3", "priority": "Medium", "severity": "MODERATE", "advisory_id": "GHSA-3"}
    f_low = {"id": "4", "priority": "Low", "severity": "LOW", "advisory_id": "GHSA-4"}

    sorted_findings = sorted([f_low, f_highest, f_medium, f_high], key=finding_sort_key)
    assert [f["priority"] for f in sorted_findings] == ["Highest", "High", "Medium", "Low"]


def test_tie_breakers_order_by_severity_within_same_band() -> None:
    """Tie-breaker 2: Within Medium, CRITICAL (no path) ranks before HIGH (no path) before LOW."""
    f_crit_no_path = {"id": "1", "priority": "Medium", "severity": "CRITICAL", "path_status": "no_path_found", "advisory_id": "GHSA-A"}
    f_high_no_path = {"id": "2", "priority": "Medium", "severity": "HIGH", "path_status": "no_path_found", "advisory_id": "GHSA-B"}
    f_low_with_path = {"id": "3", "priority": "Medium", "severity": "LOW", "path_status": "no_path_found", "advisory_id": "GHSA-C"}

    sorted_findings = sorted([f_low_with_path, f_crit_no_path, f_high_no_path], key=finding_sort_key)
    assert [f["id"] for f in sorted_findings] == ["1", "2", "3"]


def test_tie_breakers_order_by_path_depth() -> None:
    """Tie-breaker 4: Direct dependency (depth 1) ranks before transitive (depth 2)."""
    f_direct = {"id": "1", "priority": "High", "severity": "HIGH", "path_status": "path_found", "path_depth": 1, "advisory_id": "GHSA-1"}
    f_transitive = {"id": "2", "priority": "High", "severity": "HIGH", "path_status": "path_found", "path_depth": 2, "advisory_id": "GHSA-1"}

    sorted_findings = sorted([f_transitive, f_direct], key=finding_sort_key)
    assert [f["id"] for f in sorted_findings] == ["1", "2"]


def test_tie_breakers_order_by_fixed_version_presence() -> None:
    """Tie-breaker 5: Actionable remediation target ranks before unknown fix."""
    f_with_fix = {"id": "1", "priority": "High", "severity": "HIGH", "path_depth": 1, "fixed_version": "2.0.0", "advisory_id": "GHSA-1"}
    f_no_fix = {"id": "2", "priority": "High", "severity": "HIGH", "path_depth": 1, "fixed_version": None, "advisory_id": "GHSA-1"}

    sorted_findings = sorted([f_no_fix, f_with_fix], key=finding_sort_key)
    assert [f["id"] for f in sorted_findings] == ["1", "2"]


# =====================================================================
# API Integration Tests: Findings Scored with Reasons & Version
# =====================================================================

def _seed_test_env(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-scoring-1",
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
        name="Scoring Test Project",
        normalized_name="scoring test project",
        ecosystem="npm",
        description="US-301 test project",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


@pytest.mark.asyncio
async def test_api_findings_list_includes_priority_reasons_and_version(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC2 & AC3: GET /api/projects/{id}/findings returns band, reasons, and scoring_version."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [
        {
            "id": "find-1",
            "project_id": proj.id,
            "service_id": f"{proj.id}:svc",
            "service_name": "payment-api",
            "advisory_id": "GHSA-crit-0001",
            "advisory_summary": "Critical RCE",
            "severity": "CRITICAL",
            "package_name": "vulnerable-lib",
            "package_version": "1.0.0",
            "package_version_id": "npm:vulnerable-lib@1.0.0",
            "ecosystem": "npm",
            "status": "open",
            "path_depth": 1,
            "path_status": "path_found",
            "fixed_version": "1.0.1",
        }
    ]

    res = await client.get(f"/api/projects/{proj.id}/findings")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    item = data["items"][0]
    assert item["priority"] == "Highest"
    assert item["scoring_version"] == "v1.0.0"
    assert isinstance(item["priority_reasons"], list)
    assert len(item["priority_reasons"]) >= 3
    assert any("Critical" in r for r in item["priority_reasons"])
    assert any("Direct dependency" in r for r in item["priority_reasons"])


@pytest.mark.asyncio
async def test_api_finding_detail_includes_priority_reasons_and_version(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """AC2 & AC3: GET /api/projects/{id}/findings/{finding_id} returns reasons and version."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    finding = {
        "id": "find-detail-test",
        "project_id": proj.id,
        "service_id": f"{proj.id}:svc",
        "service_name": "auth-api",
        "advisory_id": "GHSA-high-0002",
        "advisory_summary": "High ReDoS",
        "severity": "HIGH",
        "package_name": "regex-lib",
        "package_version": "2.0.0",
        "package_version_id": "npm:regex-lib@2.0.0",
        "ecosystem": "npm",
        "status": "open",
        "path_depth": 2,
        "path_status": "path_found",
        "fixed_version": "2.0.1",
    }
    mock_vuln_repo.findings_override[proj.id] = [finding]

    res = await client.get(f"/api/projects/{proj.id}/findings/find-detail-test")
    assert res.status_code == 200
    item = res.json()
    assert item["priority"] == "High"
    assert item["scoring_version"] == "v1.0.0"
    assert isinstance(item["priority_reasons"], list)
    assert any("High" in r for r in item["priority_reasons"])
    assert any("Transitive dependency" in r for r in item["priority_reasons"])


@pytest.mark.asyncio
async def test_api_findings_sort_by_priority(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """US-301: Findings ranked with deterministic tie-breakers when sort_by=priority."""
    proj = _seed_test_env(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    mock_vuln_repo.findings_override[proj.id] = [
        {
            "id": "find-low",
            "project_id": proj.id,
            "service_id": f"{proj.id}:svc",
            "service_name": "svc",
            "advisory_id": "GHSA-low-0003",
            "advisory_summary": "Low info leak",
            "severity": "LOW",
            "package_name": "pkg-c",
            "package_version": "1.0.0",
            "package_version_id": "npm:pkg-c@1.0.0",
            "ecosystem": "npm",
            "status": "open",
            "path_depth": None,
            "path_status": "no_path_found",
        },
        {
            "id": "find-highest",
            "project_id": proj.id,
            "service_id": f"{proj.id}:svc",
            "service_name": "svc",
            "advisory_id": "GHSA-crit-0001",
            "advisory_summary": "Critical RCE",
            "severity": "CRITICAL",
            "package_name": "pkg-a",
            "package_version": "1.0.0",
            "package_version_id": "npm:pkg-a@1.0.0",
            "ecosystem": "npm",
            "status": "open",
            "path_depth": 1,
            "path_status": "path_found",
        },
        {
            "id": "find-high",
            "project_id": proj.id,
            "service_id": f"{proj.id}:svc",
            "service_name": "svc",
            "advisory_id": "GHSA-high-0002",
            "advisory_summary": "High severity",
            "severity": "HIGH",
            "package_name": "pkg-b",
            "package_version": "1.0.0",
            "package_version_id": "npm:pkg-b@1.0.0",
            "ecosystem": "npm",
            "status": "open",
            "path_depth": 2,
            "path_status": "path_found",
        },
    ]

    res = await client.get(f"/api/projects/{proj.id}/findings?sort_by=priority")
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 3
    assert [it["priority"] for it in items] == ["Highest", "High", "Low"]
    assert items[0]["id"] == "find-highest"
    assert items[1]["id"] == "find-high"
    assert items[2]["id"] == "find-low"
