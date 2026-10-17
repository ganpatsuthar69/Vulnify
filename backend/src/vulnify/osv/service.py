"""Service orchestrating OSV vulnerability ingestion, caching, and FalkorDB persistence."""

from datetime import datetime, timezone
import logging
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
from vulnify.schemas import OsvImportSummaryResponse

logger = logging.getLogger("vulnify")


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
            duration_ms = round((time.time() - t0) * 1000, 2)
            if self.job_repo is not None and job is not None:
                job.status = JobStatus.SUCCEEDED
                job.stage = "No package versions found to query"
                job.completed_at = int(datetime.now(timezone.utc).timestamp())
                job.duration_ms = duration_ms
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
                status="completed",
                errors=[],
                duration_ms=duration_ms,
                job_id=job.id if job else None,
            )

        # 3. Filter eligible packages with valid metadata and canonical OSV ecosystem
        eligible_items: list[tuple[PackageVersionItem, str]] = []
        skipped_count = 0
        registry = get_ecosystem_registry()

        for item in package_items:
            name = item.name.strip() if item.name else ""
            version = item.version.strip() if item.version else ""
            raw_ecosystem = item.ecosystem.strip() if item.ecosystem else ""

            if not name or not version or not raw_ecosystem:
                skipped_count += 1
                continue

            try:
                osv_eco = registry.get_osv_ecosystem(raw_ecosystem)
            except Exception:
                skipped_count += 1
                continue

            eligible_items.append((item, osv_eco))

        eligible_count = len(eligible_items)

        # 4. Group package items by unique (ecosystem, name, version) query to deduplicate lookups
        queries_to_items: dict[OsvQuery, list[PackageVersionItem]] = {}
        for item, osv_eco in eligible_items:
            q = OsvQuery(
                package=OsvPackage(name=item.name.strip(), ecosystem=osv_eco),
                version=item.version.strip(),
            )
            queries_to_items.setdefault(q, []).append(item)

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
        failed_lookups_count = 0
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
                    failed_lookups_count += 1
                    errors.append(f"{q.package.name}@{q.version}: {fail_reason}")

        # 7. Aggregate vulnerabilities and relationships for database persistence
        unique_vulnerabilities: dict[str, VulnerabilityRecord] = {}
        links_to_create: list[AdvisoryLinkRecord] = []
        packages_with_no_advisories = 0
        total_advisories_found = 0

        for q, vulns in resolved_results.items():
            if not vulns:
                packages_with_no_advisories += 1
                continue

            total_advisories_found += len(vulns)
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
            job.processed_items = total_packages
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
            packages_with_no_advisories=packages_with_no_advisories,
            skipped_packages=skipped_count,
            failed_lookups=failed_lookups_count,
            status=status,
            errors=errors,
            duration_ms=duration_ms,
            job_id=job.id if job else None,
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

