from datetime import datetime, timezone
import logging
import time
from typing import Any
import uuid

from fastapi import Depends

from vulnify.graph.job_repository import IIngestionJobRepository, get_job_repository
from vulnify.graph.vulnerability_repository import (
    IVulnerabilityRepository,
    get_vulnerability_repository,
)
from vulnify.models import IngestionJobRecord, JobStatus, JobType
from vulnify.schemas import (
    ProjectMatchResponse,
    VersionMatchResultResponse,
    VulnerabilityFindingResponse,
)
from vulnify.version_matching.models import (
    AdvisoryData,
    MatchStatus,
    VersionMatchResult,
)
from vulnify.version_matching.range_evaluator import evaluate_version_against_advisory

logger = logging.getLogger("vulnify")


class VersionMatchingService:
    """Evaluates package versions against known advisories and updates the graph."""

    def __init__(
        self,
        repo: IVulnerabilityRepository | None = None,
        job_repo: IIngestionJobRepository | None = None,
    ) -> None:
        self.repo = repo or get_vulnerability_repository()
        self.job_repo = job_repo

    def evaluate_single(
        self,
        package_name: str,
        package_version: str,
        ecosystem: str,
        advisory_payload: dict[str, Any],
    ) -> VersionMatchResult:
        """Evaluate a single package version against an arbitrary advisory payload."""
        advisory_data = AdvisoryData.from_osv_dict(advisory_payload)
        return evaluate_version_against_advisory(
            package_name=package_name,
            package_version=package_version,
            ecosystem=ecosystem,
            advisory=advisory_data,
        )

    def match_project_vulnerabilities(
        self,
        project_id: str,
        initiated_by: str | None = None,
        job_id: str | None = None,
    ) -> ProjectMatchResponse:
        """Run ecosystem-aware matching for all package-advisory pairs associated with a project."""
        t0 = time.time()
        now_ts = int(datetime.now(timezone.utc).timestamp())
        job: IngestionJobRecord | None = None

        if self.job_repo is not None:
            actual_job_id = job_id or str(uuid.uuid4())
            existing_job = self.job_repo.get_job(project_id, actual_job_id) if job_id else None
            job = IngestionJobRecord(
                id=actual_job_id,
                project_id=project_id,
                job_type=JobType.VERSION_MATCHING,
                status=JobStatus.RUNNING,
                stage="Evaluating package-advisory constraints",
                created_at=existing_job.created_at if existing_job else now_ts,
                started_at=now_ts,
                initiated_by=initiated_by or (existing_job.initiated_by if existing_job else None),
                retry_of_job_id=existing_job.retry_of_job_id if existing_job else None,
            )
            self.job_repo.upsert_job(job)

        try:
            return self._execute_matching_workflow(project_id=project_id, t0=t0, job=job)
        except Exception as exc:
            if self.job_repo is not None and job is not None:
                job.status = JobStatus.FAILED
                job.stage = f"Failed: {str(exc)}"
                job.error_summary = str(exc)
                job.errors = [str(exc)]
                job.completed_at = int(datetime.now(timezone.utc).timestamp())
                job.duration_ms = round((time.time() - t0) * 1000, 2)
                job.retry_eligible = True
                self.job_repo.upsert_job(job)
            raise

    def _execute_matching_workflow(
        self,
        project_id: str,
        t0: float,
        job: IngestionJobRecord | None,
    ) -> ProjectMatchResponse:
        pairs = self.repo.get_project_package_advisories(project_id)

        affected_matches: list[tuple[str, VersionMatchResult]] = []
        non_affected_matches: list[tuple[str, VersionMatchResult]] = []
        all_evaluations: list[VersionMatchResultResponse] = []

        affected_count = 0
        not_affected_count = 0
        unknown_count = 0

        # Cache parsed AdvisoryData by (vulnerability_id, affected_ranges) to avoid re-parsing identical advisory JSON
        parsed_advisories_cache: dict[tuple[str, str], AdvisoryData] = {}

        for pair in pairs:
            cache_key = (pair.vulnerability_id, pair.affected_ranges)
            adv = parsed_advisories_cache.get(cache_key)
            if adv is None:
                adv = AdvisoryData.from_stored(
                    vuln_id=pair.vulnerability_id,
                    affected_ranges_raw=pair.affected_ranges,
                    summary=pair.summary,
                    fallback_pkg_name=pair.package_name,
                    fallback_ecosystem=pair.ecosystem,
                )
                parsed_advisories_cache[cache_key] = adv

            result = evaluate_version_against_advisory(
                package_name=pair.package_name,
                package_version=pair.package_version,
                ecosystem=pair.ecosystem,
                advisory=adv,
            )

            response_item = VersionMatchResultResponse(
                package_name=result.package_name,
                package_version=result.package_version,
                ecosystem=result.ecosystem,
                advisory_id=result.advisory_id,
                status=result.status.value,
                reason_code=result.reason_code.value,
                reason=result.reason,
                matched_range=result.matched_range,
                fixed_version=result.fixed_version,
                comparator=result.comparator,
                evaluated_at=result.evaluated_at,
                fingerprint=result.fingerprint,
            )
            all_evaluations.append(response_item)

            if result.status == MatchStatus.AFFECTED:
                affected_count += 1
                affected_matches.append((pair.package_version_id, result))
            elif result.status == MatchStatus.NOT_AFFECTED:
                not_affected_count += 1
                non_affected_matches.append((pair.package_version_id, result))
            else:
                unknown_count += 1
                # Unknown result: do not establish AFFECTS edge, remove any stale edge
                non_affected_matches.append((pair.package_version_id, result))

        persisted_count, removed_count = self.repo.persist_match_results(
            affected_matches=affected_matches,
            non_affected_matches=non_affected_matches,
        )

        duration_ms = round((time.time() - t0) * 1000, 2)
        total_eval = len(pairs)

        if self.job_repo is not None and job is not None:
            job.total_items = total_eval
            job.processed_items = total_eval
            job.percentage = 100.0
            job.discovered_items = total_eval
            job.created_items = affected_count
            job.updated_items = persisted_count
            job.reused_items = removed_count
            job.status = JobStatus.SUCCEEDED
            job.stage = "Version matching completed successfully"
            job.completed_at = int(datetime.now(timezone.utc).timestamp())
            job.duration_ms = duration_ms
            job.retry_eligible = False
            self.job_repo.upsert_job(job)

        logger.info(
            f"Version matching finished for project {project_id}: "
            f"{total_eval} evaluated ({affected_count} affected, {not_affected_count} not affected, {unknown_count} unknown), "
            f"{persisted_count} AFFECTS persisted, {removed_count} removed in {duration_ms}ms"
        )

        return ProjectMatchResponse(
            project_id=project_id,
            total_evaluated=total_eval,
            affected_count=affected_count,
            not_affected_count=not_affected_count,
            unknown_count=unknown_count,
            relationships_persisted=persisted_count,
            relationships_removed=removed_count,
            duration_ms=duration_ms,
            status="completed",
            results=all_evaluations,
            job_id=job.id if job else None,
        )

    def get_project_findings(self, project_id: str) -> list[VulnerabilityFindingResponse]:
        """Fetch all confirmed affected vulnerability findings for a project."""
        raw_items = self.repo.get_project_vulnerabilities(project_id)
        findings: list[VulnerabilityFindingResponse] = []
        for item in raw_items:
            findings.append(
                VulnerabilityFindingResponse(
                    id=item["id"],
                    summary=item.get("summary", ""),
                    details=item.get("details", ""),
                    severity=item.get("severity", "UNKNOWN"),
                    cvss=item.get("cvss"),
                    aliases=item.get("aliases", []),
                    published=item.get("published"),
                    modified=item.get("modified"),
                    source_url=item.get("source_url", ""),
                    package_version_id=item["package_version_id"],
                    package_name=item["package_name"],
                    package_version=item["package_version"],
                    ecosystem=item["ecosystem"],
                    match_status=item["match_status"],
                    match_reason=item["match_reason"],
                    reason_code=item["reason_code"],
                    matched_range=item.get("matched_range"),
                    fixed_version=item.get("fixed_version"),
                    evaluated_at=item["evaluated_at"],
                    comparator=item.get("comparator", ""),
                    fingerprint=item.get("fingerprint", ""),
                )
            )
        return findings


def get_version_matching_service(
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
    job_repo: IIngestionJobRepository = Depends(get_job_repository),
) -> VersionMatchingService:
    return VersionMatchingService(repo=repo, job_repo=job_repo)

