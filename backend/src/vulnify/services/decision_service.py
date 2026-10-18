"""Decision & Change Detection Service (US-402).

Implements deterministic change detection for previously recorded triage decisions:
- Captures baseline evidence snapshots upon decision recording (advisory, package version, dependency path).
- Detects meaningful changes to underlying security facts according to US-402 acceptance criteria:
  "A finding marked not affected stays quiet unless the advisory, the version or the path changes;
   then it is flagged 'needs review' with the reason."
- Preserves original decision audit trail, timestamps, and justifications.
- Enforces idempotent comparisons and robust defense against noise and missing evidence.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Literal

from fastapi import HTTPException, status
from pydantic import BaseModel, Field

from vulnify.graph.vulnerability_repository import (
    IVulnerabilityRepository,
    get_vulnerability_repository,
)
from vulnify.scoring.engine import normalize_path_status, normalize_severity

logger = logging.getLogger("vulnify")


class DecisionBaseline(BaseModel):
    """Immutable snapshot of the evidence upon which a triage decision was founded."""

    advisory_id: str
    severity: str
    matched_range: str | None = None
    fixed_version: str | None = None
    summary: str | None = None
    modified: str | None = None
    package_name: str
    package_version: str
    package_version_id: str
    path_depth: int | None = None
    path_status: str = "path_found"
    fingerprint: str


class ChangeComparisonResult(BaseModel):
    """Structured result of comparing current finding evidence against recorded baseline."""

    finding_id: str
    has_changed: bool
    review_required: bool
    has_baseline: bool
    category: str | None = None  # "advisory", "version", "path", "multiple"
    reason: str | None = None
    changes: list[str] = Field(default_factory=list)
    current_evidence: dict[str, Any] = Field(default_factory=dict)
    baseline: DecisionBaseline | None = None


class DecisionRecord(BaseModel):
    """Full domain model for a finding triage decision with change review metadata."""

    project_id: str
    finding_id: str
    advisory_id: str
    package_version_id: str
    service_id: str | None = None
    status: str
    justification: str | None = None
    triaged_by: str
    triaged_at: int
    review_required: bool = False
    review_reason: str | None = None
    change_category: str | None = None
    reviewed_at: int | None = None
    reviewed_by: str | None = None
    baseline: DecisionBaseline | None = None


def compute_evidence_fingerprint(
    advisory_id: str,
    severity: str,
    matched_range: str | None,
    fixed_version: str | None,
    package_name: str,
    package_version: str,
    package_version_id: str,
    path_depth: int | None,
    path_status: str,
    modified: str | None = None,
) -> str:
    """Deterministically derive a SHA-256 digest over normalized decision-relevant evidence."""
    norm_sev = normalize_severity(severity)
    norm_path = normalize_path_status(path_status, path_depth)
    parts = [
        str(advisory_id or "").strip().lower(),
        norm_sev,
        str(matched_range or "").strip(),
        str(fixed_version or "").strip(),
        str(package_name or "").strip().lower(),
        str(package_version or "").strip(),
        str(package_version_id or "").strip(),
        str(path_depth) if path_depth is not None else "none",
        norm_path,
        str(modified or "").strip(),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DecisionService:
    """Service for managing triage decisions and detecting changes that require human review."""

    def __init__(self, repo: IVulnerabilityRepository) -> None:
        self.repo = repo

    def create_baseline_from_finding(self, finding: dict[str, Any]) -> DecisionBaseline:
        """Construct a normalized, deterministic decision baseline from current finding evidence."""
        advisory_id = str(finding.get("advisory_id", "")).strip()
        severity = normalize_severity(finding.get("severity"))
        matched_range = (
            str(finding["matched_range"]).strip()
            if finding.get("matched_range") is not None
            else None
        )
        fixed_version = (
            str(finding["fixed_version"]).strip()
            if finding.get("fixed_version") is not None
            else None
        )
        summary = (
            str(finding["advisory_summary"]).strip()
            if finding.get("advisory_summary") is not None
            else None
        )
        raw_mod = finding.get("modified") if finding.get("modified") is not None else finding.get("advisory_modified")
        modified = str(raw_mod).strip() if raw_mod is not None else None

        package_name = str(finding.get("package_name", "")).strip()
        package_version = str(finding.get("package_version", "")).strip()
        package_version_id = str(finding.get("package_version_id", "")).strip()

        raw_depth = finding.get("path_depth")
        path_depth = int(raw_depth) if raw_depth is not None else None
        path_status = normalize_path_status(finding.get("path_status"), path_depth)

        fingerprint = compute_evidence_fingerprint(
            advisory_id=advisory_id,
            severity=severity,
            matched_range=matched_range,
            fixed_version=fixed_version,
            package_name=package_name,
            package_version=package_version,
            package_version_id=package_version_id,
            path_depth=path_depth,
            path_status=path_status,
            modified=modified,
        )

        return DecisionBaseline(
            advisory_id=advisory_id,
            severity=severity,
            matched_range=matched_range,
            fixed_version=fixed_version,
            summary=summary,
            modified=modified,
            package_name=package_name,
            package_version=package_version,
            package_version_id=package_version_id,
            path_depth=path_depth,
            path_status=path_status,
            fingerprint=fingerprint,
        )

    def parse_baseline(self, raw_baseline: Any) -> DecisionBaseline | None:
        """Safely deserialize a baseline snapshot from dict or JSON string."""
        if not raw_baseline:
            return None
        if isinstance(raw_baseline, DecisionBaseline):
            return raw_baseline
        if isinstance(raw_baseline, dict):
            try:
                return DecisionBaseline(**raw_baseline)
            except Exception:
                return None
        if isinstance(raw_baseline, str) and raw_baseline.strip():
            try:
                parsed = json.loads(raw_baseline)
                if isinstance(parsed, dict):
                    return DecisionBaseline(**parsed)
            except Exception:
                return None
        return None

    def compare_evidence(
        self,
        baseline: DecisionBaseline | None,
        current_finding: dict[str, Any],
    ) -> ChangeComparisonResult:
        """Deterministically compare current authoritative evidence with recorded baseline.

        Enforces US-402 acceptance criteria:
        Detects meaningful changes across the three canonical axes:
        1. Advisory changes (severity, fixed version, range constraint, upstream modified).
        2. Version changes (package installed version or package version ID).
        3. Path changes (reachability status or shortest hop count).
        """
        finding_id = str(current_finding.get("id", ""))

        if baseline is None:
            return ChangeComparisonResult(
                finding_id=finding_id,
                has_changed=False,
                review_required=False,
                has_baseline=False,
                category=None,
                reason="No decision baseline was recorded for this historical finding.",
                changes=[],
                current_evidence=current_finding,
                baseline=None,
            )

        current_baseline = self.create_baseline_from_finding(current_finding)

        # Fast path: Identical deterministic fingerprint
        if baseline.fingerprint == current_baseline.fingerprint:
            return ChangeComparisonResult(
                finding_id=finding_id,
                has_changed=False,
                review_required=False,
                has_baseline=True,
                category=None,
                reason=None,
                changes=[],
                current_evidence=current_finding,
                baseline=baseline,
            )

        categories_detected: set[str] = set()
        change_messages: list[str] = []

        # 1. Compare Advisory evidence
        advisory_diffs = []
        if baseline.severity != current_baseline.severity:
            advisory_diffs.append(
                f"severity changed from '{baseline.severity}' to '{current_baseline.severity}'"
            )
        if baseline.fixed_version != current_baseline.fixed_version:
            advisory_diffs.append(
                f"fixed version changed from '{baseline.fixed_version or 'none'}' to '{current_baseline.fixed_version or 'none'}'"
            )
        if baseline.matched_range != current_baseline.matched_range:
            advisory_diffs.append(
                f"matched version range changed from '{baseline.matched_range or 'any'}' to '{current_baseline.matched_range or 'any'}'"
            )
        if (
            baseline.modified
            and current_baseline.modified
            and baseline.modified != current_baseline.modified
        ):
            advisory_diffs.append("advisory updated upstream by security authorities")

        if advisory_diffs:
            categories_detected.add("advisory")
            change_messages.append(f"Advisory: {'; '.join(advisory_diffs)}")

        # 2. Compare Package Version evidence
        version_diffs = []
        if baseline.package_version != current_baseline.package_version:
            version_diffs.append(
                f"installed version changed from '{baseline.package_version}' to '{current_baseline.package_version}'"
            )
        elif baseline.package_version_id != current_baseline.package_version_id:
            version_diffs.append(
                f"package version identifier changed from '{baseline.package_version_id}' to '{current_baseline.package_version_id}'"
            )

        if version_diffs:
            categories_detected.add("version")
            change_messages.append(f"Package: {'; '.join(version_diffs)}")

        # 3. Compare Dependency Path evidence
        path_diffs = []
        if baseline.path_status != current_baseline.path_status:
            path_diffs.append(
                f"reachability changed from '{baseline.path_status}' to '{current_baseline.path_status}'"
            )
        if baseline.path_depth != current_baseline.path_depth:
            b_depth_str = f"{baseline.path_depth} hop(s)" if baseline.path_depth is not None else "unknown"
            c_depth_str = f"{current_baseline.path_depth} hop(s)" if current_baseline.path_depth is not None else "unknown"
            path_diffs.append(f"shortest path depth changed from {b_depth_str} to {c_depth_str}")

        if path_diffs:
            categories_detected.add("path")
            change_messages.append(f"Path: {'; '.join(path_diffs)}")

        # If differences exist in the 3 canonical dimensions
        has_changed = len(change_messages) > 0
        if not has_changed:
            return ChangeComparisonResult(
                finding_id=finding_id,
                has_changed=False,
                review_required=False,
                has_baseline=True,
                category=None,
                reason=None,
                changes=[],
                current_evidence=current_finding,
                baseline=baseline,
            )

        category = (
            "multiple"
            if len(categories_detected) > 1
            else next(iter(categories_detected))
        )
        reason = "; ".join(change_messages)

        return ChangeComparisonResult(
            finding_id=finding_id,
            has_changed=True,
            review_required=True,
            has_baseline=True,
            category=category,
            reason=reason,
            changes=change_messages,
            current_evidence=current_finding,
            baseline=baseline,
        )

    def record_decision(
        self,
        project_id: str,
        finding_id: str,
        status: str,
        justification: str | None = None,
        triaged_by: str = "agent",
    ) -> DecisionRecord:
        """Persist a human or agent triage decision on a finding, establishing a new baseline snapshot."""
        norm_status = status.strip().lower()
        if norm_status not in ("open", "under_investigation", "affected", "not_affected", "fixed"):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid triage status '{status}'. Must be one of: open, under_investigation, affected, not_affected, fixed.",
            )

        if norm_status == "not_affected":
            if not justification or len(justification.strip()) < 10:
                raise HTTPException(
                    status_code=422,
                    detail="A written justification of at least 10 characters is required when marking a finding as 'not_affected' (US-401).",
                )

        finding = self.repo.get_project_finding_detail(project_id, finding_id)
        if not finding:
            raise HTTPException(
                status_code=404,
                detail=f"Finding '{finding_id}' not found in project '{project_id}'.",
            )

        advisory_id = finding["advisory_id"]
        package_version_id = finding["package_version_id"]
        service_id = finding.get("service_id")
        now = int(datetime.now(timezone.utc).timestamp())

        # Create baseline snapshot from current finding facts
        baseline = self.create_baseline_from_finding(finding)

        # Persist decision and baseline
        self.repo.record_triage_decision(
            project_id=project_id,
            advisory_id=advisory_id,
            package_version_id=package_version_id,
            status=norm_status,
            justification=justification.strip() if justification else None,
            triaged_by=triaged_by,
            triaged_at=now,
            baseline_data=baseline.model_dump(),
            review_required=False,
            review_reason=None,
        )

        logger.info(
            f"Recorded decision for finding '{finding_id}' in project '{project_id}': "
            f"status='{norm_status}', actor='{triaged_by}'"
        )

        return DecisionRecord(
            project_id=project_id,
            finding_id=finding_id,
            advisory_id=advisory_id,
            package_version_id=package_version_id,
            service_id=service_id,
            status=norm_status,
            justification=justification.strip() if justification else None,
            triaged_by=triaged_by,
            triaged_at=now,
            review_required=False,
            review_reason=None,
            change_category=None,
            reviewed_at=now,
            reviewed_by=triaged_by,
            baseline=baseline,
        )

    def review_decision(
        self,
        project_id: str,
        finding_id: str,
        reviewed_by: str,
        action: str = "confirm",
        new_status: str | None = None,
        new_justification: str | None = None,
        notes: str | None = None,
    ) -> DecisionRecord:
        """Acknowledge or confirm a decision that was flagged as needing review (US-402).

        Advances baseline to current authoritative evidence so future subsequent changes will be detected.
        If action is 'confirm', preserves original decision value, original triaged_by, and original triaged_at.
        If action is 'update' or 're_triage', records the new status and justification.
        """
        finding = self.repo.get_project_finding_detail(project_id, finding_id)
        if not finding:
            raise HTTPException(
                status_code=404,
                detail=f"Finding '{finding_id}' not found in project '{project_id}'.",
            )

        advisory_id = finding["advisory_id"]
        package_version_id = finding["package_version_id"]
        service_id = finding.get("service_id")
        now = int(datetime.now(timezone.utc).timestamp())

        # Establish new baseline matching the newly reviewed reality
        new_baseline = self.create_baseline_from_finding(finding)

        if action in ("update", "re_triage") and new_status:
            target_status = new_status.strip().lower()
            if target_status == "not_affected":
                if not new_justification or len(new_justification.strip()) < 10:
                    raise ValueError(
                        "A written justification of at least 10 characters is required when marking a finding as 'not_affected' (US-401)."
                    )
            final_status = target_status
            final_justification = new_justification.strip() if new_justification else finding.get("triage_justification")
            final_triaged_by = reviewed_by
            final_triaged_at = now
        else:
            final_status = finding.get("status", "open")
            final_justification = finding.get("triage_justification")
            final_triaged_by = finding.get("triaged_by", "agent")
            final_triaged_at = finding.get("triaged_at", now)

        self.repo.record_triage_decision(
            project_id=project_id,
            advisory_id=advisory_id,
            package_version_id=package_version_id,
            status=final_status,
            justification=final_justification,
            triaged_by=final_triaged_by,
            triaged_at=final_triaged_at,
            baseline_data=new_baseline.model_dump(),
            review_required=False,
            review_reason=None,
        )

        logger.info(
            f"Review acknowledged for finding '{finding_id}' in project '{project_id}' by '{reviewed_by}'. "
            f"Baseline advanced to current state."
        )

        return DecisionRecord(
            project_id=project_id,
            finding_id=finding_id,
            advisory_id=advisory_id,
            package_version_id=package_version_id,
            service_id=service_id,
            status=final_status,
            justification=final_justification,
            triaged_by=final_triaged_by,
            triaged_at=final_triaged_at,
            review_required=False,
            review_reason=None,
            change_category=None,
            reviewed_at=now,
            reviewed_by=reviewed_by,
            baseline=new_baseline,
        )

    def detect_changes_for_finding(
        self,
        project_id: str,
        finding_id: str,
    ) -> ChangeComparisonResult:
        """Run change detection for a single finding and persist updated review state if changed."""
        finding = self.repo.get_project_finding_detail(project_id, finding_id)
        if not finding:
            raise HTTPException(
                status_code=404,
                detail=f"Finding '{finding_id}' not found in project '{project_id}'.",
            )

        baseline = self.parse_baseline(finding.get("baseline_data"))
        comparison = self.compare_evidence(baseline, finding)

        # If finding was marked 'not_affected' (or has an established baseline) and evidence changed:
        status_val = str(finding.get("status", "open")).lower()
        if comparison.has_changed and status_val == "not_affected":
            if not finding.get("review_required") or finding.get("review_reason") != comparison.reason:
                self.repo.record_triage_decision(
                    project_id=project_id,
                    advisory_id=finding["advisory_id"],
                    package_version_id=finding["package_version_id"],
                    status=status_val,
                    justification=finding.get("triage_justification"),
                    triaged_by=finding.get("triaged_by", "agent"),
                    triaged_at=finding.get("triaged_at"),
                    baseline_data=baseline.model_dump() if baseline else None,
                    review_required=True,
                    review_reason=comparison.reason,
                )
                logger.warning(
                    f"Finding '{finding_id}' ({finding.get('advisory_id')}) flagged for review: {comparison.reason}"
                )

        return comparison

    def detect_changes_for_project(self, project_id: str) -> list[ChangeComparisonResult]:
        """Run change detection across all settled findings for a project.

        Idempotent and safe:
        - Only flags findings where meaningful differences exist between baseline and current graph facts.
        - Preserves prior decisions and timestamps.
        """
        findings, _ = self.repo.get_project_findings(project_id=project_id, limit=1000)
        results: list[ChangeComparisonResult] = []

        for f in findings:
            status_val = str(f.get("status", "open")).lower()
            raw_base = f.get("baseline_data")
            if not raw_base:
                continue

            baseline = self.parse_baseline(raw_base)
            if not baseline:
                continue

            # In US-402, 'not_affected' settled findings are monitored for change
            if status_val != "not_affected":
                continue

            comparison = self.compare_evidence(baseline, f)
            if comparison.has_changed:
                if not f.get("review_required") or f.get("review_reason") != comparison.reason:
                    self.repo.record_triage_decision(
                        project_id=project_id,
                        advisory_id=f["advisory_id"],
                        package_version_id=f["package_version_id"],
                        status=status_val,
                        justification=f.get("triage_justification"),
                        triaged_by=f.get("triaged_by", "agent"),
                        triaged_at=f.get("triaged_at"),
                        baseline_data=baseline.model_dump(),
                        review_required=True,
                        review_reason=comparison.reason,
                    )
                    logger.info(
                        f"Flagged decision for finding '{f['id']}' as needing review: {comparison.reason}"
                    )
            results.append(comparison)

        return results


from fastapi import Depends
from fastapi.params import Depends as DependsType


def get_decision_service(
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
) -> DecisionService:
    """Dependency injection provider for DecisionService."""
    if repo is None or isinstance(repo, DependsType):
        repo = get_vulnerability_repository()
    return DecisionService(repo=repo)
