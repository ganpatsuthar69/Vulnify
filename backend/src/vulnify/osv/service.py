"""Service orchestrating OSV vulnerability ingestion, caching, and FalkorDB persistence."""

from datetime import datetime, timezone
import logging
import re
import time
from typing import Any
import uuid

from fastapi import Depends

from vulnify.config import Settings, get_settings
from vulnify.graph.advisory_repository import (
    AdvisoryLinkRecord,
    IAdvisoryRepository,
    PackageVersionItem,
    VulnerabilityRecord,
    get_advisory_repository,
)
from vulnify.graph.job_repository import IIngestionJobRepository, get_job_repository
from vulnify.models import IngestionJobRecord, JobStatus, JobType
from vulnify.osv.cache import OsvCache, get_osv_cache
from vulnify.osv.client import OsvClient
from vulnify.osv.models import OsvPackage, OsvQuery, OsvVulnerability
from vulnify.parsers.registry import get_ecosystem_registry
from vulnify.schemas import OsvImportSummaryResponse, OsvPackageOutcomeResponse

logger = logging.getLogger("vulnify")

NON_EXACT_VERSION_PATTERN = re.compile(r"[\^~<>=*|,\s]")


class OsvService:
    """Coordinates fetching advisories from OSV, caching results, and persisting into FalkorDB."""

    def __init__(
        self,
        settings: Settings | None = None,
        advisory_repo: IAdvisoryRepository | None = None,
        client: OsvClient | None = None,
        cache: OsvCache | None = None,
        job_repo: IIngestionJobRepository | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        if advisory_repo is not None:
            self.advisory_repo = advisory_repo
        elif not self.settings.OSV_ENABLED:
            from vulnify.graph.advisory_repository import InMemoryAdvisoryRepository
            self.advisory_repo = InMemoryAdvisoryRepository()
        else:
            self.advisory_repo = get_advisory_repository()
        self.client = client or OsvClient(self.settings)
        self.cache = cache or get_osv_cache(self.settings.OSV_CACHE_TTL_SECONDS)
        self.job_repo = job_repo

    async def import_project_advisories(
        self,
        project_id: str,
        force_refresh: bool = False,
        initiated_by: str | None = None,
        job_id: str | None = None,
    ) -> OsvImportSummaryResponse:
        """Run advisory ingestion workflow for all package versions belonging to a project."""
        t0 = time.time()
        now_ts = int(datetime.now(timezone.utc).timestamp())
        job: IngestionJobRecord | None = None

        if self.job_repo is not None:
            actual_job_id = job_id or str(uuid.uuid4())
            existing_job = self.job_repo.get_job(project_id, actual_job_id) if job_id else None
            job = IngestionJobRecord(
                id=actual_job_id,
                project_id=project_id,
                job_type=JobType.OSV_SYNC,
                status=JobStatus.RUNNING,
                stage="Inspecting project package versions",
                created_at=existing_job.created_at if existing_job else now_ts,
                started_at=now_ts,
                initiated_by=initiated_by or (existing_job.initiated_by if existing_job else None),
                retry_of_job_id=existing_job.retry_of_job_id if existing_job else None,
            )
            self.job_repo.upsert_job(job)

        try:
            return await self._execute_import_workflow(
                project_id=project_id,
                force_refresh=force_refresh,
                t0=t0,
                now_ts=now_ts,
                job=job,
            )
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

    async def _execute_import_workflow(
        self,
        project_id: str,
        force_refresh: bool,
        t0: float,
        now_ts: int,
        job: IngestionJobRecord | None,
    ) -> OsvImportSummaryResponse:

        # 1. Check if OSV integration is enabled
        if not self.settings.OSV_ENABLED:
            duration_ms = round((time.time() - t0) * 1000, 2)
            if self.job_repo is not None and job is not None:
                job.status = JobStatus.SUCCEEDED
                job.stage = "OSV integration disabled"
                job.completed_at = int(datetime.now(timezone.utc).timestamp())
                job.duration_ms = duration_ms
                job.warnings = ["OSV advisory integration is disabled by configuration (OSV_ENABLED=false)."]
                self.job_repo.upsert_job(job)
            return OsvImportSummaryResponse(
                project_id=project_id,
                total_package_versions=0,
                eligible_package_versions=0,
                unique_lookups=0,
                cache_hits=0,
                advisories_found=0,
                advisories_created=0,
                advisories_updated=0,
                relationships_created=0,
                relationships_reused=0,
                packages_with_no_advisories=0,
                skipped_packages=0,
                failed_lookups=0,
                status="skipped",
                errors=["OSV advisory integration is disabled by configuration (OSV_ENABLED=false)."],
                duration_ms=duration_ms,
                job_id=job.id if job else None,
            )

        # 2. Retrieve project's persisted package versions from FalkorDB
        package_items = self.advisory_repo.get_project_package_versions(project_id)
        total_packages = len(package_items)

        if total_packages == 0:
            return self._not_scanned_summary(
                project_id=project_id,
                t0=t0,
                job=job,
                total_packages=0,
                package_results=[],
                message=(
                    "No package versions are linked to this project's services, so nothing was scanned. "
                    "Import a lockfile (for example package-lock.json) first."
                ),
            )

        # 3. Filter eligible packages with valid metadata and canonical OSV ecosystem
        eligible_items: list[tuple[int, PackageVersionItem, str]] = []
        package_results: dict[int, OsvPackageOutcomeResponse] = {}
        registry = get_ecosystem_registry()

        for idx, item in enumerate(package_items):
            name = item.name.strip() if item.name else ""
            version = item.version.strip() if item.version else ""
            raw_ecosystem = item.ecosystem.strip() if item.ecosystem else ""

            skip_reason: str | None = None
            osv_eco = ""
            if not name:
                skip_reason = "Missing package name."
            elif not version:
                skip_reason = "Missing package version."
            elif not raw_ecosystem:
                skip_reason = "Missing package ecosystem."
            elif NON_EXACT_VERSION_PATTERN.search(version):
                skip_reason = f"Version '{version}' is a range, not an exact resolved version."
            else:
                try:
                    osv_eco = registry.get_osv_ecosystem(raw_ecosystem)
                except Exception:
                    skip_reason = f"Ecosystem '{raw_ecosystem}' is not supported for OSV lookups."

            if skip_reason:
                package_results[idx] = _outcome(item, "skipped", reason=skip_reason)
                continue
            eligible_items.append((idx, item, osv_eco))

        eligible_count = len(eligible_items)
        skipped_count = total_packages - eligible_count

        if eligible_count == 0:
            return self._not_scanned_summary(
                project_id=project_id,
                t0=t0,
                job=job,
                total_packages=total_packages,
                package_results=[package_results[i] for i in sorted(package_results)],
                message=f"All {total_packages} package versions were skipped; no OSV lookups were made.",
            )

        # 4. Group package items by unique (ecosystem, name, version) query to deduplicate lookups
        queries_to_items: dict[OsvQuery, list[PackageVersionItem]] = {}
        query_for_index: dict[int, OsvQuery] = {}
        for idx, item, osv_eco in eligible_items:
            q = OsvQuery(
                package=OsvPackage(name=item.name.strip(), ecosystem=osv_eco),
                version=item.version.strip(),
            )
            queries_to_items.setdefault(q, []).append(item)
            query_for_index[idx] = q

        unique_queries = list(queries_to_items.keys())
        unique_lookups_count = len(unique_queries)

        # 5. Check cache for unexpired entries
        cache_hits_count = 0
        queries_to_fetch: list[OsvQuery] = []
        resolved_results: dict[OsvQuery, list[OsvVulnerability]] = {}

        for q in unique_queries:
            if not force_refresh:
                cached_vulns = self.cache.get(q.package.ecosystem, q.package.name, q.version)
                if cached_vulns is not None:
                    cache_hits_count += 1
                    resolved_results[q] = cached_vulns
                    continue
            queries_to_fetch.append(q)

        # 6. Fetch uncached queries in batches from OSV API
        failed_reasons: dict[OsvQuery, str] = {}
        errors: list[str] = []

        if queries_to_fetch:
            batch_size = max(1, self.settings.OSV_BATCH_SIZE)
            for i in range(0, len(queries_to_fetch), batch_size):
                chunk = queries_to_fetch[i : i + batch_size]
                batch_res, batch_fails = await self.client.query_batch(chunk)

                for q, vulns in batch_res.items():
                    resolved_results[q] = vulns
                    # Cache successful lookups (including confirmed empty results)
                    self.cache.set(
                        q.package.ecosystem,
                        q.package.name,
                        q.version,
                        vulns,
                        ttl_seconds=self.settings.OSV_CACHE_TTL_SECONDS,
                    )

                for q, fail_reason in batch_fails:
                    failed_reasons[q] = fail_reason
                    errors.append(f"{q.package.name}@{q.version}: {fail_reason}")

                for q in chunk:
                    if q not in batch_res and q not in failed_reasons:
                        failed_reasons[q] = "OSV client returned no result for this query."
                        errors.append(f"{q.package.name}@{q.version}: {failed_reasons[q]}")

        # 7. Aggregate vulnerabilities and relationships for database persistence
        unique_vulnerabilities: dict[str, VulnerabilityRecord] = {}
        links_to_create: list[AdvisoryLinkRecord] = []

        for q, vulns in resolved_results.items():
            if not vulns:
                continue

            associated_items = queries_to_items.get(q, [])

            for v in vulns:
                if v.id not in unique_vulnerabilities:
                    v.retrieved_at = now_ts
                    unique_vulnerabilities[v.id] = v

                for item in associated_items:
                    links_to_create.append(
                        AdvisoryLinkRecord(
                            package_version_id=item.id,
                            advisory_id=v.id,
                            created_at=now_ts,
                        )
                    )

        for idx, q in query_for_index.items():
            item = package_items[idx]
            if q in resolved_results:
                vulns = resolved_results[q]
                package_results[idx] = (
                    _outcome(item, "advisories_found", advisory_ids=[v.id for v in vulns])
                    if vulns
                    else _outcome(item, "no_advisories")
                )
            else:
                package_results[idx] = _outcome(item, "query_failed", reason=failed_reasons.get(q))

        ordered_results = [package_results[i] for i in sorted(package_results)]
        total_advisories_found = len({(link.package_version_id, link.advisory_id) for link in links_to_create})
        packages_with_advisories = sum(1 for r in ordered_results if r.outcome == "advisories_found")
        packages_with_no_advisories = sum(1 for r in ordered_results if r.outcome == "no_advisories")
        failed_lookups_count = sum(1 for r in ordered_results if r.outcome == "query_failed")

        # 8. Persist into FalkorDB
        adv_created, adv_updated, rel_created, rel_reused = self.advisory_repo.persist_advisories(
            list(unique_vulnerabilities.values()),
            links_to_create,
        )

        # 9. Determine overall status
        if failed_lookups_count > 0:
            status = "partial_failure" if len(resolved_results) > 0 else "failed"
        else:
            status = "completed"

        duration_ms = round((time.time() - t0) * 1000, 2)

        if self.job_repo is not None and job is not None:
            job.total_items = total_packages
            job.processed_items = eligible_count
            job.skipped_items = skipped_count
            job.percentage = 100.0
            job.discovered_items = total_advisories_found
            job.created_items = adv_created
            job.updated_items = adv_updated
            job.reused_items = rel_reused
            job.failed_items = failed_lookups_count
            job.errors = errors
            job.status = (
                JobStatus.SUCCEEDED
                if status == "completed"
                else (JobStatus.PARTIAL if status == "partial_failure" else JobStatus.FAILED)
            )
            job.stage = (
                "OSV advisory sync completed successfully"
                if job.status == JobStatus.SUCCEEDED
                else (
                    "OSV advisory sync completed with partial failures"
                    if job.status == JobStatus.PARTIAL
                    else "OSV advisory sync failed"
                )
            )
            job.completed_at = int(datetime.now(timezone.utc).timestamp())
            job.duration_ms = duration_ms
            job.retry_eligible = job.status in (JobStatus.PARTIAL, JobStatus.FAILED)
            self.job_repo.upsert_job(job)

        logger.info(
            f"OSV advisory ingestion completed for project {project_id}: "
            f"{total_packages} considered, {unique_lookups_count} lookups, "
            f"{cache_hits_count} cache hits, {total_advisories_found} advisories, "
            f"{failed_lookups_count} failed in {duration_ms}ms (status={status})"
        )

        return OsvImportSummaryResponse(
            project_id=project_id,
            total_package_versions=total_packages,
            eligible_package_versions=eligible_count,
            unique_lookups=unique_lookups_count,
            cache_hits=cache_hits_count,
            advisories_found=total_advisories_found,
            advisories_created=adv_created,
            advisories_updated=adv_updated,
            relationships_created=rel_created,
            relationships_reused=rel_reused,
            packages_with_advisories=packages_with_advisories,
            packages_with_no_advisories=packages_with_no_advisories,
            skipped_packages=skipped_count,
            failed_lookups=failed_lookups_count,
            status=status,
            errors=errors,
            duration_ms=duration_ms,
            job_id=job.id if job else None,
            package_results=ordered_results,
        )

    def _not_scanned_summary(
        self,
        project_id: str,
        t0: float,
        job: IngestionJobRecord | None,
        total_packages: int,
        package_results: list[OsvPackageOutcomeResponse],
        message: str,
    ) -> OsvImportSummaryResponse:
        duration_ms = round((time.time() - t0) * 1000, 2)
        if self.job_repo is not None and job is not None:
            job.status = JobStatus.FAILED
            job.stage = "No package versions were scanned"
            job.total_items = total_packages
            job.processed_items = 0
            job.skipped_items = total_packages
            job.error_summary = message
            job.errors = [message]
            job.completed_at = int(datetime.now(timezone.utc).timestamp())
            job.duration_ms = duration_ms
            job.retry_eligible = False
            self.job_repo.upsert_job(job)
        logger.warning(f"OSV advisory scan for project {project_id} processed no packages: {message}")
        return OsvImportSummaryResponse(
            project_id=project_id,
            total_package_versions=total_packages,
            eligible_package_versions=0,
            unique_lookups=0,
            cache_hits=0,
            advisories_found=0,
            advisories_created=0,
            advisories_updated=0,
            relationships_created=0,
            relationships_reused=0,
            packages_with_advisories=0,
            packages_with_no_advisories=0,
            skipped_packages=total_packages,
            failed_lookups=0,
            status="skipped",
            errors=[message],
            duration_ms=duration_ms,
            job_id=job.id if job else None,
            package_results=package_results,
        )


def _outcome(
    item: PackageVersionItem,
    outcome: str,
    advisory_ids: list[str] | None = None,
    reason: str | None = None,
) -> OsvPackageOutcomeResponse:
    return OsvPackageOutcomeResponse(
        package_version_id=item.id,
        name=item.name or "",
        version=item.version or "",
        ecosystem=item.ecosystem or "",
        outcome=outcome,
        advisory_ids=advisory_ids or [],
        reason=reason,
    )


def get_osv_service(
    settings: Settings = Depends(get_settings),
    advisory_repo: IAdvisoryRepository = Depends(get_advisory_repository),
    job_repo: IIngestionJobRepository = Depends(get_job_repository),
) -> OsvService:
    return OsvService(
        settings=settings,
        advisory_repo=advisory_repo,
        job_repo=job_repo,
    )

