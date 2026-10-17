"""Service orchestrating OSV vulnerability ingestion, caching, and FalkorDB persistence."""

from datetime import datetime, timezone
import logging
import time
from typing import Any

from fastapi import Depends

from vulnify.config import Settings, get_settings
from vulnify.graph.advisory_repository import (
    AdvisoryLinkRecord,
    IAdvisoryRepository,
    PackageVersionItem,
    VulnerabilityRecord,
    get_advisory_repository,
)
from vulnify.osv.cache import OsvCache, get_osv_cache
from vulnify.osv.client import OsvClient
from vulnify.osv.models import OsvPackage, OsvQuery, OsvVulnerability
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

    async def import_project_advisories(
        self,
        project_id: str,
        force_refresh: bool = False,
    ) -> OsvImportSummaryResponse:
        """Run advisory ingestion workflow for all package versions belonging to a project."""
        t0 = time.time()
        now_ts = int(datetime.now(timezone.utc).timestamp())

        # 1. Check if OSV integration is enabled
        if not self.settings.OSV_ENABLED:
            duration_ms = round((time.time() - t0) * 1000, 2)
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
            )

        # 2. Retrieve project's persisted package versions from FalkorDB
        package_items = self.advisory_repo.get_project_package_versions(project_id)
        total_packages = len(package_items)

        if total_packages == 0:
            duration_ms = round((time.time() - t0) * 1000, 2)
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
            )

        # 3. Filter eligible packages with valid metadata
        eligible_items: list[PackageVersionItem] = []
        skipped_count = 0

        for item in package_items:
            name = item.name.strip() if item.name else ""
            version = item.version.strip() if item.version else ""
            ecosystem = item.ecosystem.strip() if item.ecosystem else ""

            if not name or not version or not ecosystem:
                skipped_count += 1
                continue
            eligible_items.append(item)

        eligible_count = len(eligible_items)

        # 4. Group package items by unique (ecosystem, name, version) query to deduplicate lookups
        queries_to_items: dict[OsvQuery, list[PackageVersionItem]] = {}
        for item in eligible_items:
            q = OsvQuery(
                package=OsvPackage(name=item.name.strip(), ecosystem=item.ecosystem.strip()),
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
        )


def get_osv_service(
    settings: Settings = Depends(get_settings),
    advisory_repo: IAdvisoryRepository = Depends(get_advisory_repository),
) -> OsvService:
    return OsvService(
        settings=settings,
        advisory_repo=advisory_repo,
    )
