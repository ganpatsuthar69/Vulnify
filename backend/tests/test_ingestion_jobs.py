"""Automated unit and integration tests for US-105: Ingestion Jobs and History."""

import io
import json
import uuid
import pytest
from httpx import AsyncClient

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.graph.job_repository import InMemoryIngestionJobRepository
from vulnify.graph.project_repository import InMemoryProjectRepository, ProjectRecord
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.models import IngestionJobRecord, JobStatus, JobType

MINIMAL_VALID_PACKAGE_LOCK = json.dumps({
    "name": "sample-project",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "name": "sample-project",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.2"
            }
        },
        "node_modules/express": {
            "version": "4.18.2",
            "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            "integrity": "sha512-5/psL6iVEkiGu9pe45ecE8GcwURSkOBZJ2UrVEUic201EE22hw806PYy6MVn2SU6PEUa9mgvmwwAF8797g5tFQ==",
            "dependencies": {
                "accepts": "~1.3.8"
            }
        },
        "node_modules/accepts": {
            "version": "1.3.8",
            "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
            "integrity": "sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw+NACSaeXEQ+NHcVF7rONl630kc84khTrWURGQPHI9A=="
        }
    }
}).encode("utf-8")


@pytest.fixture(autouse=True)
def seed_admin_user(mock_user_repo: InMemoryUserRepository) -> None:
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


@pytest.fixture
def test_project(mock_project_repo: InMemoryProjectRepository) -> ProjectRecord:
    return mock_project_repo.create_project(
        name="Security Ingestion Project",
        ecosystem="npm",
        description="Test project for ingestion jobs",
    )


@pytest.mark.asyncio
async def test_dependency_import_creates_succeeded_job(
    client: AsyncClient,
    test_project: ProjectRecord,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """Successful dependency import creates an IngestionJob record with succeeded status and returns job_id."""
    authenticate_client(client)

    res = await client.post(
        f"/api/projects/{test_project.id}/dependencies/import",
        json={
            "service_name": "api-gateway",
            "filename": "package-lock.json",
            "content": MINIMAL_VALID_PACKAGE_LOCK.decode("utf-8"),
            "import_method": "npm_lockfile",
        },
    )
    assert res.status_code == 200
    res_data = res.json()
    assert "job_id" in res_data
    assert res_data["job_id"] is not None

    job_id = res_data["job_id"]
    job = mock_job_repo.get_job(test_project.id, job_id)
    assert job is not None
    assert job.status == JobStatus.SUCCEEDED
    assert job.job_type == JobType.DEPENDENCY_IMPORT
    assert job.service_name == "api-gateway"
    assert job.processed_items == 2
    assert job.filename == "package-lock.json"
    assert job.ecosystem == "npm"
    assert job.sha256_hash is not None
    assert job.duration_ms is not None
    assert job.completed_at is not None


@pytest.mark.asyncio
async def test_dependency_import_failure_records_failed_job(
    client: AsyncClient,
    test_project: ProjectRecord,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """Invalid lockfile import records a failed IngestionJob with error summary."""
    authenticate_client(client)

    res = await client.post(
        f"/api/projects/{test_project.id}/dependencies/import",
        json={
            "service_name": "api-gateway",
            "filename": "package-lock.json",
            "content": "Not valid JSON content {{{",
            "import_method": "npm_lockfile",
        },
    )
    assert res.status_code == 422

    # Check that failed job was recorded
    jobs, total, _ = mock_job_repo.list_jobs(test_project.id)
    assert total >= 1
    failed_job = jobs[0]
    assert failed_job.status == JobStatus.FAILED
    assert failed_job.job_type == JobType.DEPENDENCY_IMPORT
    assert failed_job.error_summary is not None
    assert len(failed_job.errors) > 0


@pytest.mark.asyncio
async def test_osv_sync_and_version_matching_record_jobs(
    client: AsyncClient,
    test_project: ProjectRecord,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """OSV sync and version matching create and complete IngestionJob records."""
    authenticate_client(client)

    # 1. Trigger OSV sync
    osv_res = await client.post(
        f"/api/projects/{test_project.id}/advisories/import",
        json={"force_refresh": True},
    )
    assert osv_res.status_code == 200
    osv_data = osv_res.json()
    assert osv_data.get("job_id") is not None
    osv_job = mock_job_repo.get_job(test_project.id, osv_data["job_id"])
    assert osv_job is not None
    assert osv_job.job_type == JobType.OSV_SYNC
    assert osv_job.status == JobStatus.SUCCEEDED

    # 2. Trigger Version Matching
    match_res = await client.post(
        f"/api/projects/{test_project.id}/vulnerabilities/match",
    )
    assert match_res.status_code == 200
    match_data = match_res.json()
    assert match_data.get("job_id") is not None
    match_job = mock_job_repo.get_job(test_project.id, match_data["job_id"])
    assert match_job is not None
    assert match_job.job_type == JobType.VERSION_MATCHING
    assert match_job.status == JobStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_list_jobs_with_filtering_and_pagination(
    client: AsyncClient,
    test_project: ProjectRecord,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """List endpoint correctly paginates and applies filters and summary metrics."""
    authenticate_client(client)

    # Seed jobs
    job1 = IngestionJobRecord(
        id=str(uuid.uuid4()),
        project_id=test_project.id,
        service_id="srv-1",
        service_name="backend-core",
        job_type=JobType.DEPENDENCY_IMPORT,
        status=JobStatus.SUCCEEDED,
        created_at=1000,
        completed_at=1005,
    )
    job2 = IngestionJobRecord(
        id=str(uuid.uuid4()),
        project_id=test_project.id,
        job_type=JobType.OSV_SYNC,
        status=JobStatus.FAILED,
        error_summary="Network timeout contacting OSV API",
        created_at=2000,
        completed_at=2010,
    )
    job3 = IngestionJobRecord(
        id=str(uuid.uuid4()),
        project_id=test_project.id,
        job_type=JobType.VERSION_MATCHING,
        status=JobStatus.RUNNING,
        created_at=3000,
    )
    mock_job_repo.upsert_job(job1)
    mock_job_repo.upsert_job(job2)
    mock_job_repo.upsert_job(job3)

    # 1. List all
    res = await client.get(f"/api/projects/{test_project.id}/jobs")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3
    # Check ordering DESC
    assert data["items"][0]["id"] == job3.id
    # Summary stats
    stats = data["summary_stats"]
    assert stats["total_runs"] == 3
    assert stats["running_runs"] == 1
    assert stats["succeeded_runs"] == 1
    assert stats["failed_runs"] == 1
    assert stats["partial_runs"] == 0

    # 2. Filter by status=failed
    res_failed = await client.get(f"/api/projects/{test_project.id}/jobs?status=failed")
    assert res_failed.status_code == 200
    failed_data = res_failed.json()
    assert failed_data["total"] == 1
    assert failed_data["items"][0]["id"] == job2.id

    # 3. Filter by job_type=dependency_import
    res_type = await client.get(f"/api/projects/{test_project.id}/jobs?job_type=dependency_import")
    assert res_type.status_code == 200
    type_data = res_type.json()
    assert type_data["total"] == 1
    assert type_data["items"][0]["id"] == job1.id

    # 4. Filter by service_name=backend
    res_svc = await client.get(f"/api/projects/{test_project.id}/jobs?service_name=backend")
    assert res_svc.status_code == 200
    svc_data = res_svc.json()
    assert svc_data["total"] == 1
    assert svc_data["items"][0]["id"] == job1.id

    # 5. Pagination validation
    res_p_err = await client.get(f"/api/projects/{test_project.id}/jobs?page=0")
    assert res_p_err.status_code == 422
    res_ps_err = await client.get(f"/api/projects/{test_project.id}/jobs?page_size=101")
    assert res_ps_err.status_code == 422


@pytest.mark.asyncio
async def test_get_single_job_details(
    client: AsyncClient,
    test_project: ProjectRecord,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """Retrieve details for a specific ingestion job or return 404."""
    authenticate_client(client)

    job = IngestionJobRecord(
        id=str(uuid.uuid4()),
        project_id=test_project.id,
        service_id="srv-1",
        service_name="payment-svc",
        job_type=JobType.DEPENDENCY_IMPORT,
        status=JobStatus.SUCCEEDED,
        stage="Completed",
        processed_items=15,
        total_items=15,
        percentage=100,
        created_at=5000,
        completed_at=5002,
        duration_ms=2000,
        initiated_by="admin@vulnify.local",
        filename="package-lock.json",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ecosystem="npm",
        import_method="lockfile",
        fidelity="high",
        warnings=["Non-critical warning"],
    )
    mock_job_repo.upsert_job(job)

    # 1. Existing job
    res = await client.get(f"/api/projects/{test_project.id}/jobs/{job.id}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == job.id
    assert data["service_name"] == "payment-svc"
    assert data["processed_items"] == 15
    assert data["fidelity"] == "high"
    assert len(data["warnings"]) == 1

    # 2. Nonexistent job
    res_missing = await client.get(f"/api/projects/{test_project.id}/jobs/unknown-job-id")
    assert res_missing.status_code == 404

    # 3. Job belonging to another project
    res_wrong_proj = await client.get(f"/api/projects/other-project-id/jobs/{job.id}")
    assert res_wrong_proj.status_code in (404, 400)


@pytest.mark.asyncio
async def test_retry_job_workflow(
    client: AsyncClient,
    test_project: ProjectRecord,
    mock_job_repo: InMemoryIngestionJobRepository,
) -> None:
    """Retry logic adheres to eligibility, status constraints, and creates linked jobs."""
    authenticate_client(client)

    # 1. Cannot retry a succeeded job
    succeeded_job = IngestionJobRecord(
        id="succeeded-job-id",
        project_id=test_project.id,
        job_type=JobType.OSV_SYNC,
        status=JobStatus.SUCCEEDED,
        retry_eligible=True,
        created_at=1000,
    )
    mock_job_repo.upsert_job(succeeded_job)

    res_succ = await client.post(f"/api/projects/{test_project.id}/jobs/{succeeded_job.id}/retry")
    assert res_succ.status_code == 400
    res_succ_err = res_succ.json().get("message", res_succ.json().get("detail", ""))
    assert "Only failed or partial jobs are eligible" in res_succ_err

    # 2. Cannot retry a job marked retry_eligible=False
    ineligible_job = IngestionJobRecord(
        id="ineligible-job-id",
        project_id=test_project.id,
        job_type=JobType.OSV_SYNC,
        status=JobStatus.FAILED,
        retry_eligible=False,
        created_at=2000,
    )
    mock_job_repo.upsert_job(ineligible_job)

    res_inel = await client.post(f"/api/projects/{test_project.id}/jobs/{ineligible_job.id}/retry")
    assert res_inel.status_code == 400
    res_inel_err = res_inel.json().get("message", res_inel.json().get("detail", ""))
    assert "not eligible for retry" in res_inel_err

    # 3. Retrying a dependency_import job requires re-upload
    dep_job = IngestionJobRecord(
        id="failed-dep-job",
        project_id=test_project.id,
        job_type=JobType.DEPENDENCY_IMPORT,
        status=JobStatus.FAILED,
        retry_eligible=True,
        created_at=3000,
    )
    mock_job_repo.upsert_job(dep_job)

    res_dep = await client.post(f"/api/projects/{test_project.id}/jobs/{dep_job.id}/retry")
    assert res_dep.status_code == 400
    res_dep_err = res_dep.json().get("message", res_dep.json().get("detail", ""))
    assert "requires re-uploading the dependency file" in res_dep_err

    # 4. Retrying a failed OSV sync job succeeds and links retry_of_job_id
    failed_osv_job = IngestionJobRecord(
        id="failed-osv-job",
        project_id=test_project.id,
        job_type=JobType.OSV_SYNC,
        status=JobStatus.FAILED,
        retry_eligible=True,
        created_at=4000,
    )
    mock_job_repo.upsert_job(failed_osv_job)

    res_retry_osv = await client.post(f"/api/projects/{test_project.id}/jobs/{failed_osv_job.id}/retry")
    assert res_retry_osv.status_code == 200
    retry_data = res_retry_osv.json()
    assert retry_data["original_job_id"] == failed_osv_job.id
    new_job = retry_data["new_job"]
    assert new_job["retry_of_job_id"] == failed_osv_job.id
    assert new_job["status"] == JobStatus.SUCCEEDED
    # Original job is preserved
    orig_preserved = mock_job_repo.get_job(test_project.id, failed_osv_job.id)
    assert orig_preserved is not None
    assert orig_preserved.status == JobStatus.FAILED
