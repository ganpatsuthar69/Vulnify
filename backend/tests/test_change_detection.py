"""Tests for US-402: Implement change detection for previously recorded decisions.

Acceptance Criteria & Product Rules:
1. Canonical rule: Settled findings ('not_affected') stay quiet unless the advisory,
   version, or path changes; then it is flagged 'needs review' with the reason.
2. Ranking and agent workflows both read prior decisions and reflect review flags.
3. Ranking bypasses Rule 1 suppression when a finding is flagged for review,
   ranking it by true underlying risk and appending TRIAGE_NEEDS_REVIEW.
4. Summary metrics (findings_needing_decision) include decisions flagged for review.
5. Deterministic fingerprinting and noise resistance (formatting, timestamps).
6. Human review workflow: acknowledging a review clears the flag, advances the baseline,
   and preserves the original decision and audit trail.
7. End-to-end API endpoints for recording, comparing, and reviewing decisions.
"""

from typing import Any
from fastapi import HTTPException
from httpx import AsyncClient
import pytest

from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import (
    InMemoryVulnerabilityRepository,
    set_vulnerability_repository_override,
)
from vulnify.scoring.engine import score_finding
from vulnify.services.decision_service import (
    DecisionService,
)
from vulnify.agent.tools.get_finding_details import handle_get_finding_details, GetFindingDetailsInput
from vulnify.agent.tools.rank_findings import handle_rank_findings, RankFindingsInput
from vulnify.agent.tools.list_findings import handle_list_findings, ListFindingsInput
from tests.conftest import ADMIN_USER, authenticate_client


def _seed_test_project_and_user(
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    project_id: str = "proj-us402-1",
    project_name: str = "Decision Review Test Project",
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
        description="Test project for US-402 change detection",
        created_at=1700000000,
    )
    mock_project_repo._projects_by_id[proj.id] = proj
    mock_project_repo._projects_by_norm[proj.normalized_name] = proj
    return proj


def _seed_finding(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    project_id: str = "proj-us402-1",
    finding_id: str = "find-us402-001",
    advisory_id: str = "OSV-EXAMPLE-402",
    package_name: str = "sample-auth-lib",
    package_version: str = "2.1.0",
    package_version_id: str = "npm:sample-auth-lib@2.1.0",
    service_id: str = "proj-us402-1:auth-service",
    service_name: str = "auth-service",
    severity: str = "HIGH",
    matched_range: str = "< 2.2.0",
    fixed_version: str = "2.2.0",
    advisory_modified: str = "2024-01-15T12:00:00Z",
    path_depth: int = 1,
    path_status: str = "path_found",
    status: str = "open",
    justification: str | None = None,
) -> dict[str, Any]:
    finding = {
        "id": finding_id,
        "project_id": project_id,
        "service_id": service_id,
        "service_name": service_name,
        "advisory_id": advisory_id,
        "advisory_summary": "Sample advisory for change detection testing",
        "package_name": package_name,
        "ecosystem": "npm",
        "package_version": package_version,
        "package_version_id": package_version_id,
        "priority": "High",
        "priority_reasons": ["Advisory severity is High"],
        "scoring_version": "v1.0.0",
        "status": status,
        "path_depth": path_depth,
        "path_status": path_status,
        "match_reason": f"Version {package_version} is within affected range {matched_range}.",
        "reason_code": "WITHIN_AFFECTED_RANGE",
        "matched_range": matched_range,
        "fixed_version": fixed_version,
        "severity": severity,
        "advisory_modified": advisory_modified,
        "modified": advisory_modified,
        "retrieved_at": 1700000000,
        "review_required": False,
        "review_reason": None,
        "triaged_by": None,
        "triaged_at": None,
        "triage_justification": justification,
        "baseline_data": None,
        "reviewed_at": None,
    }

    if project_id not in mock_vuln_repo.findings_override:
        mock_vuln_repo.findings_override[project_id] = []

    existing_idx = next(
        (i for i, x in enumerate(mock_vuln_repo.findings_override[project_id]) if x["id"] == finding_id),
        None,
    )
    if existing_idx is not None:
        mock_vuln_repo.findings_override[project_id][existing_idx] = finding
    else:
        mock_vuln_repo.findings_override[project_id].append(finding)

    return finding


def _update_finding(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
    project_id: str,
    finding_id: str,
    **updates: Any,
) -> dict[str, Any]:
    for f in mock_vuln_repo.findings_override.get(project_id, []):
        if f["id"] == finding_id:
            f.update(updates)
            return f
    raise KeyError(f"Finding {finding_id} not found in project {project_id}")


# =====================================================================
# Unit Tests: Evidence Comparison & Fingerprinting
# =====================================================================

def test_compare_evidence_unchanged(mock_vuln_repo: InMemoryVulnerabilityRepository):
    service = DecisionService(repo=mock_vuln_repo)
    finding = _seed_finding(mock_vuln_repo)

    baseline = service.create_baseline_from_finding(finding)
    comparison = service.compare_evidence(baseline, finding)

    assert comparison.has_changed is False
    assert comparison.review_required is False
    assert comparison.has_baseline is True
    assert comparison.category is None
    assert comparison.reason is None
    assert len(comparison.changes) == 0


def test_compare_evidence_advisory_changes(mock_vuln_repo: InMemoryVulnerabilityRepository):
    service = DecisionService(repo=mock_vuln_repo)
    finding = _seed_finding(mock_vuln_repo, severity="MODERATE")
    baseline = service.create_baseline_from_finding(finding)

    # 1. Severity changed
    changed_finding = dict(finding)
    changed_finding["severity"] = "CRITICAL"
    res1 = service.compare_evidence(baseline, changed_finding)
    assert res1.has_changed is True
    assert res1.category == "advisory"
    assert "severity changed from 'MODERATE' to 'CRITICAL'" in res1.reason

    # 2. Matched range changed
    changed_range = dict(finding)
    changed_range["matched_range"] = "< 3.0.0"
    res2 = service.compare_evidence(baseline, changed_range)
    assert res2.has_changed is True
    assert res2.category == "advisory"
    assert "matched version range changed" in res2.reason

    # 3. Fixed version changed
    changed_fix = dict(finding)
    changed_fix["fixed_version"] = "2.3.0"
    res3 = service.compare_evidence(baseline, changed_fix)
    assert res3.has_changed is True
    assert res3.category == "advisory"
    assert "fixed version changed" in res3.reason

    # 4. Advisory modified date updated upstream
    changed_mod = dict(finding)
    changed_mod["modified"] = "2024-06-01T12:00:00Z"
    changed_mod["advisory_modified"] = "2024-06-01T12:00:00Z"
    res4 = service.compare_evidence(baseline, changed_mod)
    assert res4.has_changed is True
    assert res4.category == "advisory"
    assert "advisory updated upstream" in res4.reason


def test_compare_evidence_version_changes(mock_vuln_repo: InMemoryVulnerabilityRepository):
    service = DecisionService(repo=mock_vuln_repo)
    finding = _seed_finding(mock_vuln_repo, package_version="2.1.0")
    baseline = service.create_baseline_from_finding(finding)

    changed_finding = dict(finding)
    changed_finding["package_version"] = "2.1.5"
    changed_finding["package_version_id"] = "npm:sample-auth-lib@2.1.5"

    res = service.compare_evidence(baseline, changed_finding)
    assert res.has_changed is True
    assert res.category == "version"
    assert "installed version changed from '2.1.0' to '2.1.5'" in res.reason


def test_compare_evidence_path_changes(mock_vuln_repo: InMemoryVulnerabilityRepository):
    service = DecisionService(repo=mock_vuln_repo)
    finding = _seed_finding(mock_vuln_repo, path_depth=2, path_status="path_found")
    baseline = service.create_baseline_from_finding(finding)

    # Depth changed
    changed_depth = dict(finding)
    changed_depth["path_depth"] = 1
    res1 = service.compare_evidence(baseline, changed_depth)
    assert res1.has_changed is True
    assert res1.category == "path"
    assert "shortest path depth changed from 2 hop(s) to 1 hop(s)" in res1.reason

    # Path status changed from path_found to no_path_found
    changed_status = dict(finding)
    changed_status["path_status"] = "no_path_found"
    changed_status["path_depth"] = None
    res2 = service.compare_evidence(baseline, changed_status)
    assert res2.has_changed is True
    assert res2.category == "path"
    assert "reachability changed from 'path_found' to 'no_path_found'" in res2.reason


def test_compare_evidence_multiple_changes(mock_vuln_repo: InMemoryVulnerabilityRepository):
    service = DecisionService(repo=mock_vuln_repo)
    finding = _seed_finding(mock_vuln_repo, severity="MODERATE", path_depth=3)
    baseline = service.create_baseline_from_finding(finding)

    changed_finding = dict(finding)
    changed_finding["severity"] = "CRITICAL"
    changed_finding["path_depth"] = 1

    res = service.compare_evidence(baseline, changed_finding)
    assert res.has_changed is True
    assert res.category == "multiple"
    assert "Advisory:" in res.reason and "Path:" in res.reason
    assert len(res.changes) == 2


def test_compare_evidence_ignores_non_semantic_noise(mock_vuln_repo: InMemoryVulnerabilityRepository):
    service = DecisionService(repo=mock_vuln_repo)
    finding = _seed_finding(mock_vuln_repo, severity="HIGH", package_version="1.0.0")
    baseline = service.create_baseline_from_finding(finding)

    # Whitespace and case normalization
    noisy_finding = dict(finding)
    noisy_finding["severity"] = " high  "
    noisy_finding["package_name"] = " sample-auth-lib "

    res = service.compare_evidence(baseline, noisy_finding)
    assert res.has_changed is False
    assert res.category is None


def test_missing_baseline_handles_safely(mock_vuln_repo: InMemoryVulnerabilityRepository):
    service = DecisionService(repo=mock_vuln_repo)
    finding = _seed_finding(mock_vuln_repo)

    # Baseline is None (legacy record)
    res = service.compare_evidence(None, finding)
    assert res.has_changed is False
    assert res.has_baseline is False
    assert res.review_required is False


# =====================================================================
# Decision Service: Lifecycle, Acknowledgment, and Persistence
# =====================================================================

def test_record_decision_enforces_justification_for_not_affected(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
):
    service = DecisionService(repo=mock_vuln_repo)
    finding = _seed_finding(mock_vuln_repo)

    # Short justification (< 10 chars) must raise HTTPException/ValueError
    with pytest.raises((HTTPException, ValueError), match="at least 10 characters"):
        service.record_decision(
            project_id=finding["project_id"],
            finding_id=finding["id"],
            status="not_affected",
            justification="too short",
            triaged_by="sec-admin",
        )

    # Valid justification records decision and baseline snapshot
    record = service.record_decision(
        project_id=finding["project_id"],
        finding_id=finding["id"],
        status="not_affected",
        justification="Verified dependency call is isolated and unreachable from external ingress",
        triaged_by="sec-admin",
    )
    assert record.status == "not_affected"
    assert record.review_required is False
    assert record.baseline is not None
    assert record.baseline.severity == "HIGH"
    assert record.baseline.fingerprint is not None


def test_change_detection_flags_settled_finding_and_preserves_history(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
):
    service = DecisionService(repo=mock_vuln_repo)
    finding = _seed_finding(mock_vuln_repo, severity="MODERATE")

    # 1. Record settled decision
    initial = service.record_decision(
        project_id=finding["project_id"],
        finding_id=finding["id"],
        status="not_affected",
        justification="Mitigated by internal network segmentation policy",
        triaged_by="alice@vulnify.local",
    )
    original_triaged_at = initial.triaged_at

    # 2. Run detection while unchanged -> quiet
    comp_quiet = service.detect_changes_for_finding(finding["project_id"], finding["id"])
    assert comp_quiet.has_changed is False
    assert comp_quiet.review_required is False

    # 3. Simulate authoritative evidence update: advisory upgraded from MODERATE to CRITICAL
    _update_finding(mock_vuln_repo, finding["project_id"], finding["id"], severity="CRITICAL")

    # 4. Run detection -> flagged for review!
    comp_flagged = service.detect_changes_for_finding(finding["project_id"], finding["id"])
    assert comp_flagged.has_changed is True
    assert comp_flagged.review_required is True
    assert "severity changed from 'MODERATE' to 'CRITICAL'" in comp_flagged.reason

    # Verify persisted finding has review_required=True and preserved original triage actor/time
    persisted = mock_vuln_repo.get_project_finding_detail(finding["project_id"], finding["id"])
    assert persisted["review_required"] is True
    assert persisted["triaged_by"] == "alice@vulnify.local"
    assert persisted["triaged_at"] == original_triaged_at
    assert persisted["triage_justification"] == "Mitigated by internal network segmentation policy"

    # 5. Review and confirm decision -> clears flag, advances baseline
    reviewed = service.review_decision(
        project_id=finding["project_id"],
        finding_id=finding["id"],
        reviewed_by="bob@vulnify.local",
        action="confirm",
    )
    assert reviewed.review_required is False
    assert reviewed.review_reason is None
    assert reviewed.reviewed_by == "bob@vulnify.local"
    assert reviewed.triaged_by == "alice@vulnify.local"
    assert reviewed.triaged_at == original_triaged_at
    assert reviewed.baseline.severity == "CRITICAL"

    # 6. Subsequent run is quiet against new baseline
    comp_quiet_again = service.detect_changes_for_finding(finding["project_id"], finding["id"])
    assert comp_quiet_again.has_changed is False
    assert comp_quiet_again.review_required is False


# =====================================================================
# Scoring Engine & Summary Cards Integration
# =====================================================================

def test_scoring_engine_bypasses_rule1_when_review_required():
    # Settled without review flag -> Low priority (Rule 1 suppression)
    res_quiet = score_finding(
        severity="CRITICAL",
        path_status="path_found",
        path_depth=1,
        fixed_version="1.0.1",
        triage_status="not_affected",
        review_required=False,
    )
    assert res_quiet.priority == "Low"
    assert any("not_affected" in r.lower() or "resolved" in r.lower() for r in res_quiet.reasons)
    assert not any("review" in r.lower() for r in res_quiet.reasons)

    # Settled WITH review flag -> Rule 1 bypassed! Scores by true risk (Highest) & flags review
    res_flagged = score_finding(
        severity="CRITICAL",
        path_status="path_found",
        path_depth=1,
        fixed_version="1.0.1",
        triage_status="not_affected",
        review_required=True,
        review_reason="Advisory severity changed from 'MODERATE' to 'CRITICAL'",
    )
    assert res_flagged.priority == "Highest"
    assert any("requires review" in r.lower() for r in res_flagged.reasons)
    assert "TRIAGE_NEEDS_REVIEW" in res_flagged.reason_codes


def test_findings_needing_decision_summary_metric(mock_vuln_repo: InMemoryVulnerabilityRepository):
    project_id = "proj-metric-test"
    # Finding 1: open -> needs decision
    _seed_finding(mock_vuln_repo, project_id=project_id, finding_id="f1", status="open")
    # Finding 2: settled not_affected, quiet -> does NOT need decision
    f2 = _seed_finding(mock_vuln_repo, project_id=project_id, finding_id="f2", status="not_affected")
    f2["review_required"] = False
    # Finding 3: settled not_affected, but flagged needs review -> DOES need decision!
    f3 = _seed_finding(mock_vuln_repo, project_id=project_id, finding_id="f3", status="not_affected")
    f3["review_required"] = True
    f3["review_reason"] = "Package version changed"

    summary = mock_vuln_repo.get_project_findings_summary(project_id=project_id)
    # f1 (open) + f3 (review_required) = 2
    assert summary["findings_needing_decision"] == 2


# =====================================================================
# Agent Tools Integration
# =====================================================================

@pytest.mark.asyncio
async def test_agent_tools_read_prior_decisions_and_review_state(
    mock_vuln_repo: InMemoryVulnerabilityRepository,
):
    set_vulnerability_repository_override(mock_vuln_repo)
    project_id = "proj-agent-test"

    f = _seed_finding(mock_vuln_repo, project_id=project_id, finding_id="f-agent-1", status="not_affected")
    f["review_required"] = True
    f["review_reason"] = "Advisory affected range expanded"
    f["triage_justification"] = "Original justification note"

    # 1. get_finding_details tool
    detail_res = await handle_get_finding_details(
        GetFindingDetailsInput(project_id=project_id, finding_id="f-agent-1")
    )
    assert detail_res.found is True
    assert detail_res.finding is not None
    assert detail_res.finding.review_required is True
    assert detail_res.finding.review_reason == "Advisory affected range expanded"
    assert "needs review" in detail_res.trace.result_summary.lower()

    # 2. list_findings tool
    list_res = await handle_list_findings(
        ListFindingsInput(project_id=project_id)
    )
    assert list_res.total >= 1
    found = next((item for item in list_res.items if item.id == "f-agent-1"), None)
    assert found is not None
    assert found.review_required is True
    assert found.review_reason == "Advisory affected range expanded"

    # 3. rank_findings tool
    rank_res = await handle_rank_findings(
        RankFindingsInput(project_id=project_id)
    )
    ranked_item = next((item for item in rank_res.ranked_findings if item.id == "f-agent-1"), None)
    assert ranked_item is not None
    assert ranked_item.review_required is True
    assert ranked_item.review_reason == "Advisory affected range expanded"


# =====================================================================
# API Endpoints Integration
# =====================================================================

@pytest.mark.asyncio
async def test_decision_and_review_api_workflow(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
):
    project = _seed_test_project_and_user(mock_user_repo, mock_project_repo)
    authenticate_client(client)
    finding = _seed_finding(mock_vuln_repo, project_id=project.id, severity="MODERATE")

    # 1. Validation failure: not_affected without 10-char justification
    res_bad = await client.post(
        f"/api/projects/{project.id}/findings/{finding['id']}/decision",
        json={"status": "not_affected", "justification": "short"},
    )
    assert res_bad.status_code == 422

    # 2. Record valid decision
    res_dec = await client.post(
        f"/api/projects/{project.id}/findings/{finding['id']}/decision",
        json={
            "status": "not_affected",
            "justification": "Dependency is quarantined and cannot receive unauthenticated requests",
        },
    )
    assert res_dec.status_code == 200
    data = res_dec.json()
    assert data["status"] == "not_affected"
    assert data["review_required"] is False
    assert data["baseline"] is not None

    # 3. Check comparison endpoint when quiet
    res_comp1 = await client.get(
        f"/api/projects/{project.id}/findings/{finding['id']}/decision"
    )
    assert res_comp1.status_code == 200
    data_comp1 = res_comp1.json()
    assert data_comp1["has_changed"] is False
    assert data_comp1["review_required"] is False

    # 4. Mutate evidence: upgrade severity
    _update_finding(mock_vuln_repo, project.id, finding["id"], severity="HIGH")

    # 5. Trigger project-wide change detection endpoint
    res_scan = await client.post(
        f"/api/projects/{project.id}/decisions/detect-changes"
    )
    assert res_scan.status_code == 200
    scan_data = res_scan.json()
    assert scan_data["evaluated_count"] >= 1
    assert scan_data["flagged_count"] == 1

    # 6. Check single finding decision endpoint -> flagged!
    res_comp2 = await client.get(
        f"/api/projects/{project.id}/findings/{finding['id']}/decision"
    )
    assert res_comp2.status_code == 200
    data_comp2 = res_comp2.json()
    assert data_comp2["has_changed"] is True
    assert data_comp2["review_required"] is True
    assert "severity changed from 'MODERATE' to 'HIGH'" in data_comp2["reason"]

    # 7. Acknowledge and confirm review
    res_rev = await client.post(
        f"/api/projects/{project.id}/findings/{finding['id']}/review",
        json={"action": "confirm", "notes": "Reviewed and acknowledged new HIGH severity"},
    )
    assert res_rev.status_code == 200
    rev_data = res_rev.json()
    assert rev_data["review_required"] is False
    assert rev_data["baseline"]["severity"] == "HIGH"

    # 8. Subsequent comparison is quiet
    res_comp3 = await client.get(
        f"/api/projects/{project.id}/findings/{finding['id']}/decision"
    )
    assert res_comp3.status_code == 200
    assert res_comp3.json()["has_changed"] is False
