"""Data Quality Evaluation Service (US-207).

Evaluates data quality warnings across projects and findings:
- Missing topology: Detects when service-to-service topology or architectural exposure data is absent.
- Stale advisory data: Detects advisories retrieved older than the established 7-day freshness policy threshold.
- Partial imports: Detects when IngestionJobs ended in partial/failed status or contain skipped/failed items.
- No-path disclaimer: Explains search scope and depth limits; guarantees honest safety messaging.
"""

from datetime import datetime, timezone
import logging
from typing import Any

from vulnify.config import Settings, get_settings
from vulnify.graph.job_repository import IIngestionJobRepository, get_job_repository
from vulnify.graph.vulnerability_repository import (
    IVulnerabilityRepository,
    get_vulnerability_repository,
)
from vulnify.models import JobStatus
from vulnify.schemas import DataQualityWarning

logger = logging.getLogger("vulnify")

ADVISORY_FRESHNESS_THRESHOLD_DAYS = 7
ADVISORY_FRESHNESS_THRESHOLD_SECONDS = ADVISORY_FRESHNESS_THRESHOLD_DAYS * 86400


class DataQualityService:
    """Service for evaluating data quality warnings and honest empty states."""

    def __init__(
        self,
        vuln_repo: IVulnerabilityRepository,
        job_repo: IIngestionJobRepository,
        freshness_threshold_days: int = ADVISORY_FRESHNESS_THRESHOLD_DAYS,
    ) -> None:
        self.vuln_repo = vuln_repo
        self.job_repo = job_repo
        self.freshness_threshold_days = freshness_threshold_days

    def evaluate_project_warnings(self, project_id: str) -> list[DataQualityWarning]:
        """Evaluate project-level data quality warnings (topology, advisory freshness, and imports)."""
        warnings: list[DataQualityWarning] = []
        now = int(datetime.now(timezone.utc).timestamp())
        threshold_seconds = self.freshness_threshold_days * 86400

        # 1. Missing Topology Detection (AC-2)
        try:
            topo_info = self.vuln_repo.get_project_topology_info(project_id)
            service_count = topo_info.get("service_count", 0)
            call_edge_count = topo_info.get("call_edge_count", 0)

            if service_count > 0 and call_edge_count == 0:
                warnings.append(
                    DataQualityWarning(
                        code="MISSING_TOPOLOGY",
                        category="missing_topology",
                        severity="warning",
                        title="Missing Service Topology",
                        message=(
                            "Service-to-service call topology has not been imported. "
                            "Dependency paths reflect internal service dependencies only and "
                            "cannot verify architectural exposure from external ingress or across services."
                        ),
                        details={
                            "service_count": service_count,
                            "call_edge_count": call_edge_count,
                        },
                    )
                )
        except Exception as exc:
            logger.warning("Failed to evaluate topology warnings for project %s: %s", project_id, exc)

        # 2. Advisory Freshness Policy Detection (AC-2: 7-day cutoff)
        try:
            freshness = self.vuln_repo.get_project_advisories_freshness(project_id)
            total_advisories = freshness.get("total_advisories", 0)
            newest_retrieved_at = freshness.get("newest_retrieved_at")
            missing_ts_count = freshness.get("missing_timestamp_count", 0)

            if total_advisories > 0:
                if missing_ts_count > 0:
                    warnings.append(
                        DataQualityWarning(
                            code="UNKNOWN_ADVISORY_FRESHNESS",
                            category="stale_advisory_data",
                            severity="warning",
                            title="Unknown Advisory Freshness",
                            message=(
                                f"{missing_ts_count} of {total_advisories} advisories in this project "
                                "do not have a recorded retrieval timestamp. Freshness cannot be verified."
                            ),
                            details={
                                "missing_timestamp_count": missing_ts_count,
                                "total_advisories": total_advisories,
                            },
                        )
                    )

                if newest_retrieved_at is not None and newest_retrieved_at > 0:
                    age_seconds = now - newest_retrieved_at
                    if age_seconds > threshold_seconds:
                        age_days = age_seconds // 86400
                        warnings.append(
                            DataQualityWarning(
                                code="STALE_ADVISORY_DATA",
                                category="stale_advisory_data",
                                severity="warning",
                                title="Stale Advisory Data",
                                message=(
                                    f"Advisory data for this project was last refreshed {age_days} days ago, "
                                    f"exceeding the {self.freshness_threshold_days}-day freshness policy threshold. "
                                    "Newly published vulnerabilities or patched versions may not be reflected."
                                ),
                                details={
                                    "threshold_days": self.freshness_threshold_days,
                                    "last_retrieved_at": newest_retrieved_at,
                                    "age_days": age_days,
                                },
                            )
                        )
        except Exception as exc:
            logger.warning("Failed to evaluate advisory freshness for project %s: %s", project_id, exc)

        # 3. Partial Ingestion Detection (AC-2)
        try:
            jobs, _, _ = self.job_repo.list_jobs(project_id=project_id, limit=20)
            problematic_job = None
            for j in jobs:
                status_str = str(j.status).lower()
                if (
                    status_str in (JobStatus.PARTIAL, JobStatus.FAILED, "partial", "failed")
                    or (j.failed_items and j.failed_items > 0)
                    or (j.skipped_items and j.skipped_items > 0)
                ):
                    problematic_job = j
                    break

            if problematic_job:
                warnings.append(
                    DataQualityWarning(
                        code="PARTIAL_IMPORT_DETECTED",
                        category="partial_import",
                        severity="warning",
                        title="Incomplete Dependency Ingestion",
                        message=(
                            f"Ingestion job '{problematic_job.id}' ({problematic_job.job_type}) "
                            f"terminated with {problematic_job.status} status "
                            f"({problematic_job.failed_items} failed, {problematic_job.skipped_items} skipped items). "
                            "Analysis may be based on an incomplete dependency graph."
                        ),
                        resource_id=problematic_job.id,
                        details={
                            "job_id": problematic_job.id,
                            "job_type": problematic_job.job_type,
                            "status": str(problematic_job.status),
                            "failed_items": problematic_job.failed_items,
                            "skipped_items": problematic_job.skipped_items,
                            "service_name": problematic_job.service_name,
                        },
                    )
                )
        except Exception as exc:
            logger.warning("Failed to evaluate ingestion jobs for project %s: %s", project_id, exc)

        return warnings

    def evaluate_finding_warnings(
        self,
        project_id: str,
        finding: dict[str, Any],
    ) -> list[DataQualityWarning]:
        """Evaluate combined project-wide and finding-specific data quality warnings."""
        warnings = self.evaluate_project_warnings(project_id)
        now = int(datetime.now(timezone.utc).timestamp())
        threshold_seconds = self.freshness_threshold_days * 86400

        # AC-1: Honest no-path message
        path_status = str(finding.get("path_status", "")).lower()
        path_depth = finding.get("path_depth")
        has_path = path_depth is not None and path_depth >= 1 and path_status != "no_path_found"

        if not has_path:
            warnings.append(
                DataQualityWarning(
                    code="NO_PATH_DISCLAIMER",
                    category="no_path",
                    severity="info",
                    title="No Path Found Does Not Guarantee Safety",
                    message=(
                        "No dependency path was found within the maximum traversal depth. "
                        "'No path found' does not guarantee safety: the target package version is present "
                        "in the project's dependency manifest and may still be reached via dynamically resolved dependencies, "
                        "undeclared service calls, or out-of-scope services."
                    ),
                    resource_id=finding.get("id"),
                    details={
                        "finding_id": finding.get("id"),
                        "package_name": finding.get("package_name"),
                        "package_version": finding.get("package_version"),
                        "service_name": finding.get("service_name"),
                    },
                )
            )

        # Finding-specific advisory freshness check if finding has a specific retrieved_at
        f_retrieved_at = finding.get("retrieved_at")
        if f_retrieved_at is None or f_retrieved_at == 0:
            if not any(w.code == "UNKNOWN_ADVISORY_FRESHNESS" for w in warnings):
                warnings.append(
                    DataQualityWarning(
                        code="UNKNOWN_ADVISORY_FRESHNESS",
                        category="stale_advisory_data",
                        severity="warning",
                        title="Unknown Advisory Freshness",
                        message=(
                            f"Advisory '{finding.get('advisory_id')}' does not have a recorded retrieval timestamp. "
                            "Freshness cannot be verified."
                        ),
                        resource_id=finding.get("advisory_id"),
                        details={"finding_id": finding.get("id"), "advisory_id": finding.get("advisory_id")},
                    )
                )
        else:
            age_seconds = now - int(f_retrieved_at)
            if age_seconds > threshold_seconds:
                age_days = age_seconds // 86400
                if not any(w.code == "STALE_ADVISORY_DATA" for w in warnings):
                    warnings.append(
                        DataQualityWarning(
                            code="STALE_ADVISORY_DATA",
                            category="stale_advisory_data",
                            severity="warning",
                            title="Stale Advisory Data",
                            message=(
                                f"Advisory '{finding.get('advisory_id')}' was last refreshed {age_days} days ago, "
                                f"exceeding the {self.freshness_threshold_days}-day freshness policy threshold."
                            ),
                            resource_id=finding.get("advisory_id"),
                            details={
                                "finding_id": finding.get("id"),
                                "advisory_id": finding.get("advisory_id"),
                                "last_retrieved_at": f_retrieved_at,
                                "age_days": age_days,
                                "threshold_days": self.freshness_threshold_days,
                            },
                        )
                    )

        # Deduplicate warnings by code
        deduped: list[DataQualityWarning] = []
        seen_codes: set[str] = set()
        for w in warnings:
            if w.code not in seen_codes:
                seen_codes.add(w.code)
                deduped.append(w)

        return deduped


from fastapi import Depends

def get_data_quality_service(
    vuln_repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
    job_repo: IIngestionJobRepository = Depends(get_job_repository),
) -> DataQualityService:
    return DataQualityService(vuln_repo=vuln_repo, job_repo=job_repo)
