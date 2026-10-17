"""Ingestion Job repository for persistent tracking of dependency imports, OSV sync, and matching jobs."""

import json
import logging
from typing import Any, Protocol

from vulnify.config import get_settings
from vulnify.graph.client import GraphClient, get_graph_client, load_query
from vulnify.models import IngestionJobRecord, JobStatus

logger = logging.getLogger("vulnify")


class IIngestionJobRepository(Protocol):
    """Protocol for ingestion job persistence and query operations."""

    def upsert_job(self, job: IngestionJobRecord) -> IngestionJobRecord:
        """Create or update an IngestionJob record."""
        ...

    def get_job(self, project_id: str, job_id: str) -> IngestionJobRecord | None:
        """Retrieve an IngestionJob by project_id and job_id."""
        ...

    def list_jobs(
        self,
        project_id: str,
        status: str | None = None,
        job_type: str | None = None,
        service_name: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[IngestionJobRecord], int, dict[str, int]]:
        """List ingestion jobs for a project with optional filters and pagination.

        Returns (items, total_matching, summary_stats).
        """
        ...


class FalkorIngestionJobRepository:
    """FalkorDB graph implementation of IIngestionJobRepository."""

    def __init__(self, client: GraphClient | None = None) -> None:
        self.client = client or get_graph_client()
        self._query_upsert = load_query("upsert_ingestion_job.cypher")
        self._query_get = load_query("get_ingestion_job.cypher")
        self._query_list = load_query("list_ingestion_jobs.cypher")

    def _row_to_record(self, row: list[Any]) -> IngestionJobRecord:
        errors_raw = row[17]
        warnings_raw = row[18]
        errors = json.loads(errors_raw) if errors_raw and isinstance(errors_raw, str) else (errors_raw or [])
        warnings = json.loads(warnings_raw) if warnings_raw and isinstance(warnings_raw, str) else (warnings_raw or [])

        return IngestionJobRecord(
            id=str(row[0]),
            project_id=str(row[1]),
            job_type=str(row[2]),
            status=str(row[3]),
            stage=str(row[4]),
            service_id=str(row[5]) if row[5] is not None else None,
            service_name=str(row[6]) if row[6] is not None else None,
            processed_items=int(row[7]) if row[7] is not None else 0,
            total_items=int(row[8]) if row[8] is not None else None,
            percentage=float(row[9]) if row[9] is not None else None,
            discovered_items=int(row[10]) if row[10] is not None else 0,
            created_items=int(row[11]) if row[11] is not None else 0,
            updated_items=int(row[12]) if row[12] is not None else 0,
            reused_items=int(row[13]) if row[13] is not None else 0,
            skipped_items=int(row[14]) if row[14] is not None else 0,
            failed_items=int(row[15]) if row[15] is not None else 0,
            error_summary=str(row[16]) if row[16] is not None else None,
            errors=errors,
            warnings=warnings,
            retry_eligible=bool(row[19]) if row[19] is not None else False,
            retry_of_job_id=str(row[20]) if row[20] is not None else None,
            created_at=int(row[21]) if row[21] is not None else 0,
            started_at=int(row[22]) if row[22] is not None else None,
            completed_at=int(row[23]) if row[23] is not None else None,
            duration_ms=float(row[24]) if row[24] is not None else None,
            initiated_by=str(row[25]) if row[25] is not None else None,
            filename=str(row[26]) if row[26] is not None else None,
            secondary_filename=str(row[27]) if row[27] is not None else None,
            sha256_hash=str(row[28]) if row[28] is not None else None,
            ecosystem=str(row[29]) if row[29] is not None else None,
            import_method=str(row[30]) if row[30] is not None else None,
            fidelity=str(row[31]) if row[31] is not None else None,
            metadata_json=str(row[32]) if row[32] is not None else None,
        )

    def upsert_job(self, job: IngestionJobRecord) -> IngestionJobRecord:
        graph = self.client.get_graph()
        params = {
            "id": job.id,
            "project_id": job.project_id,
            "job_type": job.job_type,
            "status": job.status,
            "stage": job.stage,
            "service_id": job.service_id,
            "service_name": job.service_name,
            "processed_items": job.processed_items,
            "total_items": job.total_items,
            "percentage": job.percentage,
            "discovered_items": job.discovered_items,
            "created_items": job.created_items,
            "updated_items": job.updated_items,
            "reused_items": job.reused_items,
            "skipped_items": job.skipped_items,
            "failed_items": job.failed_items,
            "error_summary": job.error_summary,
            "errors_json": json.dumps(job.errors),
            "warnings_json": json.dumps(job.warnings),
            "retry_eligible": job.retry_eligible,
            "retry_of_job_id": job.retry_of_job_id,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "duration_ms": job.duration_ms,
            "initiated_by": job.initiated_by,
            "filename": job.filename,
            "secondary_filename": job.secondary_filename,
            "sha256_hash": job.sha256_hash,
            "ecosystem": job.ecosystem,
            "import_method": job.import_method,
            "fidelity": job.fidelity,
            "metadata_json": job.metadata_json,
        }
        graph.query(self._query_upsert, params)
        return job

    def get_job(self, project_id: str, job_id: str) -> IngestionJobRecord | None:
        graph = self.client.get_graph()
        result = graph.query(self._query_get, {"project_id": project_id, "job_id": job_id})
        if not result.result_set:
            return None
        return self._row_to_record(result.result_set[0])

    def list_jobs(
        self,
        project_id: str,
        status: str | None = None,
        job_type: str | None = None,
        service_name: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[IngestionJobRecord], int, dict[str, int]]:
        graph = self.client.get_graph()
        result = graph.query(self._query_list, {"project_id": project_id})

        all_records: list[IngestionJobRecord] = []
        if result.result_set:
            for row in result.result_set:
                all_records.append(self._row_to_record(row))

        summary_stats = {
            "total_runs": len(all_records),
            "running_runs": sum(1 for r in all_records if r.status in (JobStatus.RUNNING, JobStatus.QUEUED)),
            "succeeded_runs": sum(1 for r in all_records if r.status == JobStatus.SUCCEEDED),
            "failed_runs": sum(1 for r in all_records if r.status == JobStatus.FAILED),
            "partial_runs": sum(1 for r in all_records if r.status == JobStatus.PARTIAL),
        }

        # Apply filters
        filtered = all_records
        if status:
            filtered = [r for r in filtered if r.status == status]
        if job_type:
            filtered = [r for r in filtered if r.job_type == job_type]
        if service_name:
            norm_service = service_name.lower().strip()
            filtered = [r for r in filtered if r.service_name and norm_service in r.service_name.lower()]

        total_matching = len(filtered)
        paginated = filtered[offset : offset + limit]
        return paginated, total_matching, summary_stats


class InMemoryIngestionJobRepository:
    """In-memory implementation for isolated unit testing and mock mode."""

    def __init__(self) -> None:
        self._jobs: dict[str, IngestionJobRecord] = {}

    def upsert_job(self, job: IngestionJobRecord) -> IngestionJobRecord:
        self._jobs[job.id] = job
        return job

    def get_job(self, project_id: str, job_id: str) -> IngestionJobRecord | None:
        job = self._jobs.get(job_id)
        if job and job.project_id == project_id:
            return job
        return None

    def list_jobs(
        self,
        project_id: str,
        status: str | None = None,
        job_type: str | None = None,
        service_name: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[IngestionJobRecord], int, dict[str, int]]:
        project_jobs = [j for j in self._jobs.values() if j.project_id == project_id]
        project_jobs.sort(key=lambda j: j.created_at, reverse=True)

        summary_stats = {
            "total_runs": len(project_jobs),
            "running_runs": sum(1 for r in project_jobs if r.status in (JobStatus.RUNNING, JobStatus.QUEUED)),
            "succeeded_runs": sum(1 for r in project_jobs if r.status == JobStatus.SUCCEEDED),
            "failed_runs": sum(1 for r in project_jobs if r.status == JobStatus.FAILED),
            "partial_runs": sum(1 for r in project_jobs if r.status == JobStatus.PARTIAL),
        }

        filtered = project_jobs
        if status:
            filtered = [r for r in filtered if r.status == status]
        if job_type:
            filtered = [r for r in filtered if r.job_type == job_type]
        if service_name:
            norm_service = service_name.lower().strip()
            filtered = [r for r in filtered if r.service_name and norm_service in r.service_name.lower()]

        total_matching = len(filtered)
        paginated = filtered[offset : offset + limit]
        return paginated, total_matching, summary_stats


def get_job_repository() -> IIngestionJobRepository:
    """FastAPI dependency for obtaining the configured ingestion job repository."""
    return FalkorIngestionJobRepository()
