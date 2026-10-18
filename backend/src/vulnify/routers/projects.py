import asyncio
from datetime import datetime, timezone
import email
import hashlib
import math
import time
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from vulnify.config import Settings, get_settings
from vulnify.dependencies import get_valid_project, require_admin, require_auth
from vulnify.graph.advisory_repository import IAdvisoryRepository, get_advisory_repository
from vulnify.graph.dependency_repository import IDependencyRepository, get_dependency_repository
from vulnify.graph.job_repository import IIngestionJobRepository, get_job_repository
from vulnify.graph.project_repository import (
    IProjectRepository,
    ProjectRecord,
    get_project_repository,
)
from vulnify.graph.vulnerability_repository import (
    IVulnerabilityRepository,
    get_vulnerability_repository,
)
from vulnify.models import IngestionJobRecord, JobStatus, JobType
from vulnify.osv.service import OsvService, get_osv_service
from vulnify.parsers.models import DependencyParseError, LockfileParseError
from vulnify.parsers.registry import (
    EcosystemCapabilitiesResponse,
    get_ecosystem_registry,
    get_supported_ecosystem_ids,
)
from vulnify.schemas import (
    SERVICE_NAME_REGEX,
    SUPPORTED_ECOSYSTEMS,
    FindingItemResponse,
    FindingListResponse,
    FindingSummaryResponse,
    FindingDetailResponse,
    FindingPathsResponse,
    ProjectExposurePathsResponse,
    ArchitecturalExposureItem,
    DataQualityWarning,
    ProjectDataQualityResponse,
    ImportSummaryResponse,
    IngestionJobListResponse,
    IngestionJobResponse,
    IngestionJobSummaryStats,
    JobRetryResponse,
    OsvImportSummaryResponse,
    ProjectAdvisoryResponse,
    ProjectCreateRequest,
    ProjectMatchResponse,
    ProjectResponse,
    ProjectServiceResponse,
    PackageVersionResponse,
    UserResponse,
    VulnerabilityFindingResponse,
    UpgradeCandidateItem,
    UpgradeCandidatesResponse,
    ProjectUpgradeCandidatesResponse,
    SimulationRequest,
    SimulationResponse,
    SimulationListResponse,
    GitHubIntegrationStatusResponse,
    GitHubConfigResponse,
    GitHubConfigUpdateRequest,
    GitHubConfigValidateRequest,
    GitHubValidationResultResponse,
    GitHubIssuePreviewRequest,
    GitHubIssuePreviewResponse,
    GitHubIssueCreateRequest,
    GitHubIssueRecordResponse,
    GitHubIssueListResponse,
    TriageDecisionRequest,
    ReviewDecisionRequest,
    TriageDecisionResponse,
    ChangeComparisonResponse,
)
from vulnify.services.decision_service import (
    DecisionService,
    get_decision_service,
)
from vulnify.services.data_quality import (
    DataQualityService,
    get_data_quality_service,
)
from vulnify.services.fix_simulation import (
    FixSimulationService,
    get_fix_simulation_service,
)
from vulnify.services.github_service import (
    GitHubService,
    get_github_service,
)
from vulnify.services.upgrade_candidates import (
    UpgradeCandidatesService,
    get_upgrade_candidates_service,
)
from vulnify.version_matching.service import (
    VersionMatchingService,
    get_version_matching_service,
)

router = APIRouter(prefix="/api/projects", tags=["projects"])

# Async lock to ensure serial execution of project name check-and-create across concurrent requests
_create_project_lock = asyncio.Lock()


def _extract_multipart(
    body: bytes, content_type: str
) -> tuple[str | None, str | None, bytes | None, str | None, bytes | None, str | None]:
    """Parse multipart/form-data using standard library email parser."""
    msg = email.message_from_bytes(f"Content-Type: {content_type}\r\n\r\n".encode("latin-1") + body)
    service_name = None
    filename = None
    file_bytes = None
    secondary_filename = None
    secondary_file_bytes = None
    import_method = None

    if msg.is_multipart():
        for part in msg.get_payload():
            cd_name = part.get_param("name", header="content-disposition")
            if cd_name == "service_name":
                payload = part.get_payload(decode=True)
                if payload:
                    service_name = payload.decode("utf-8", errors="replace").strip()
            elif cd_name == "import_method":
                payload = part.get_payload(decode=True)
                if payload:
                    import_method = payload.decode("utf-8", errors="replace").strip()
            elif cd_name == "file":
                filename = part.get_filename() or "package-lock.json"
                file_bytes = part.get_payload(decode=True)
            elif cd_name in ("secondary_file", "paired_file", "go_sum"):
                secondary_filename = part.get_filename() or "go.sum"
                secondary_file_bytes = part.get_payload(decode=True)
    return service_name, filename, file_bytes, secondary_filename, secondary_file_bytes, import_method


@router.get(
    "",
    response_model=list[ProjectResponse],
    status_code=status.HTTP_200_OK,
    summary="List all projects",
)
async def list_projects(
    current_user: UserResponse = Depends(require_auth),
    repo: IProjectRepository = Depends(get_project_repository),
) -> list[ProjectResponse]:
    """Retrieve all projects available to the authenticated user ordered by creation date."""
    try:
        user_id = str(current_user.id) if current_user.role != "admin" else None
        records = repo.list_projects(user_id=user_id)
        return [
            ProjectResponse(
                id=r.id,
                name=r.name,
                ecosystem=r.ecosystem,
                description=r.description,
                created_at=r.created_at,
                created_by=r.created_by,
            )
            for r in records
        ]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve projects from database.",
        ) from exc


@router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new project",
)
async def create_project(
    project_data: ProjectCreateRequest,
    current_user: UserResponse = Depends(require_auth),
    repo: IProjectRepository = Depends(get_project_repository),
) -> ProjectResponse:
    """Create and persist a new project node in FalkorDB.
    
    Enforces case-insensitive project name uniqueness and valid package ecosystem.
    """
    async with _create_project_lock:
        normalized_name = project_data.name.strip().lower()
        existing = repo.get_by_normalized_name(normalized_name)
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A project with this name already exists.",
            )

        try:
            record = repo.create_project(
                name=project_data.name,
                ecosystem=project_data.ecosystem,
                description=project_data.description,
                created_by=str(current_user.id),
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to persist project in database.",
            ) from exc

    return ProjectResponse(
        id=record.id,
        name=record.name,
        ecosystem=record.ecosystem,
        description=record.description,
        created_at=record.created_at,
        created_by=record.created_by,
    )


@router.get(
    "/ecosystems",
    summary="List supported ecosystems",
)
async def get_supported_ecosystems(
    current_user: UserResponse = Depends(require_auth),
) -> dict[str, Any]:
    """Return the list of package ecosystems supported by the system."""
    registry = get_ecosystem_registry()
    return {
        "supported_ecosystems": registry.get_supported_ecosystem_ids(),
        "capabilities": [cap.model_dump() for cap in registry.get_capabilities()],
    }


@router.get(
    "/ecosystem-capabilities",
    response_model=EcosystemCapabilitiesResponse,
    summary="Retrieve typed ecosystem capabilities and format metadata",
)
async def get_ecosystem_capabilities(
    current_user: UserResponse = Depends(require_auth),
) -> EcosystemCapabilitiesResponse:
    """Return typed capability models for all genuinely implemented and tested ecosystems."""
    registry = get_ecosystem_registry()
    return EcosystemCapabilitiesResponse(
        supported_ecosystems=registry.get_supported_ecosystem_ids(),
        capabilities=registry.get_capabilities(),
    )


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    status_code=status.HTTP_200_OK,
    summary="Get project by ID",
)
async def get_project(
    project_id: str,
    project: ProjectRecord = Depends(get_valid_project),
) -> ProjectResponse:
    """Retrieve details of a specific project by its stable identifier."""
    return ProjectResponse(
        id=project.id,
        name=project.name,
        ecosystem=project.ecosystem,
        description=project.description,
        created_at=project.created_at,
        created_by=project.created_by,
    )


@router.post(
    "/{project_id}/dependencies/import",
    response_model=ImportSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Import dependency graph from lockfile",
)
async def import_dependencies(
    project_id: str,
    request: Request,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    dep_repo: IDependencyRepository = Depends(get_dependency_repository),
    job_repo: IIngestionJobRepository = Depends(get_job_repository),
    settings: Settings = Depends(get_settings),
) -> ImportSummaryResponse:
    """Parse and persist dependency graph from an uploaded lockfile for a named service.

    Accepts multipart/form-data (service_name, file) or application/json.
    Ensures safe no-code-execution parsing, project ecosystem compatibility,
    idempotent persistence, and provenance tracking.
    """
    # 1. Check Content-Length header against max upload size limit
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.MAX_UPLOAD_SIZE_BYTES:
                max_mb = settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)
                raise HTTPException(
                    status_code=413,
                    detail=f"File size exceeds the maximum allowed limit of {max_mb} MB.",
                )
        except ValueError:
            pass

    # 3. Read body and enforce size limit
    body = await request.body()
    if len(body) > settings.MAX_UPLOAD_SIZE_BYTES:
        max_mb = settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"File size exceeds the maximum allowed limit of {max_mb} MB.",
        )

    raw_content_type = request.headers.get("content-type", "")
    content_type = raw_content_type.lower()
    service_name: str | None = None
    filename: str | None = None
    file_bytes: bytes | None = None
    secondary_filename: str | None = None
    secondary_file_bytes: bytes | None = None
    import_method: str | None = None

    if "multipart/form-data" in content_type:
        service_name, filename, file_bytes, secondary_filename, secondary_file_bytes, import_method = _extract_multipart(body, raw_content_type)
    elif "application/json" in content_type:
        try:
            import json
            json_data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            raise HTTPException(
                status_code=422,
                detail="Invalid JSON payload.",
            )
        if not isinstance(json_data, dict):
            raise HTTPException(
                status_code=422,
                detail="Request body must be a JSON object.",
            )
        service_name = json_data.get("service_name")
        filename = json_data.get("filename")
        raw_content = json_data.get("content")
        if isinstance(raw_content, str):
            file_bytes = raw_content.encode("utf-8")
        secondary_filename = json_data.get("secondary_filename")
        raw_secondary = json_data.get("secondary_content")
        if isinstance(raw_secondary, str):
            secondary_file_bytes = raw_secondary.encode("utf-8")
        import_method = json_data.get("import_method")
    else:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported media type. Request must be multipart/form-data or application/json.",
        )

    # 4. Validate service_name
    if not service_name or not service_name.strip():
        raise HTTPException(
            status_code=422,
            detail="Service name cannot be empty or whitespace only.",
        )
    service_name = service_name.strip()
    if len(service_name) > 100:
        raise HTTPException(
            status_code=422,
            detail="Service name cannot exceed 100 characters.",
        )
    if not SERVICE_NAME_REGEX.match(service_name):
        raise HTTPException(
            status_code=422,
            detail="Service name may only contain letters, numbers, underscores, hyphens, and periods.",
        )

    # 5. Validate file presence
    if file_bytes is None or len(file_bytes) == 0:
        raise HTTPException(
            status_code=422,
            detail="Lockfile must be provided and cannot be empty.",
        )
    filename = (filename or "package-lock.json").strip()

    # 6. Resolve capability and import method from backend registry
    registry = get_ecosystem_registry()
    cap = registry.get_capability(project.ecosystem)
    if not cap:
        raise HTTPException(
            status_code=422,
            detail=f"Project ecosystem '{project.ecosystem}' is not supported for dependency import. Supported ecosystems are: {', '.join(registry.get_supported_ecosystem_ids())}.",
        )

    try:
        method = registry.resolve_import_method(project.ecosystem, filename, method_id=import_method)
    except DependencyParseError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    # Enforce file-size limit from capability
    if len(file_bytes) > cap.max_file_size_bytes:
        max_mb = cap.max_file_size_bytes // (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"File size exceeds the maximum allowed limit of {max_mb} MB.",
        )
    if secondary_file_bytes is not None and len(secondary_file_bytes) > cap.max_file_size_bytes:
        max_mb = cap.max_file_size_bytes // (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"Secondary file size exceeds the maximum allowed limit of {max_mb} MB.",
        )

    # 7. Compute SHA-256 hash of primary file
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    t0 = time.time()
    now_ts = int(datetime.now(timezone.utc).timestamp())
    job_id = str(uuid.uuid4())
    user_identity = getattr(current_user, "email", None) or str(current_user.id)
    job = IngestionJobRecord(
        id=job_id,
        project_id=project.id,
        service_id=f"{project.id}:{service_name}",
        service_name=service_name,
        job_type=JobType.DEPENDENCY_IMPORT,
        status=JobStatus.RUNNING,
        stage=f"Parsing dependencies with {cap.id} parser",
        created_at=now_ts,
        started_at=now_ts,
        initiated_by=user_identity,
        filename=filename,
        secondary_filename=secondary_filename,
        sha256_hash=sha256_hash,
        ecosystem=cap.id,
        import_method=method.id,
        fidelity=method.fidelity,
    )
    job_repo.upsert_job(job)

    # 8. Parse file without code execution using the capability parser
    parser = registry.get_parser(project.ecosystem)
    try:
        parsed_graph = parser.parse(
            content=file_bytes,
            filename=filename,
            secondary_content=secondary_file_bytes,
            secondary_filename=secondary_filename,
        )
    except (DependencyParseError, LockfileParseError) as exc:
        job.status = JobStatus.FAILED
        job.stage = f"Parse failed: {str(exc)}"
        job.error_summary = str(exc)
        job.errors = [str(exc)]
        job.completed_at = int(datetime.now(timezone.utc).timestamp())
        job.duration_ms = round((time.time() - t0) * 1000, 2)
        job.retry_eligible = True
        job_repo.upsert_job(job)
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        job.status = JobStatus.FAILED
        job.stage = "Parse failed: Failed to parse lockfile contents."
        job.error_summary = "Failed to parse lockfile contents."
        job.errors = ["Failed to parse lockfile contents."]
        job.completed_at = int(datetime.now(timezone.utc).timestamp())
        job.duration_ms = round((time.time() - t0) * 1000, 2)
        job.retry_eligible = True
        job_repo.upsert_job(job)
        raise HTTPException(
            status_code=422,
            detail="Failed to parse lockfile contents.",
        ) from exc

    # Check package limit
    if len(parsed_graph.packages) > cap.max_packages:
        msg = f"Parsed package count ({len(parsed_graph.packages)}) exceeds maximum allowed limit of {cap.max_packages}."
        job.status = JobStatus.FAILED
        job.stage = f"Limit exceeded: {msg}"
        job.error_summary = msg
        job.errors = [msg]
        job.completed_at = int(datetime.now(timezone.utc).timestamp())
        job.duration_ms = round((time.time() - t0) * 1000, 2)
        job.retry_eligible = True
        job_repo.upsert_job(job)
        raise HTTPException(
            status_code=422,
            detail=msg,
        )

    # 9. Persist into FalkorDB
    try:
        summary = dep_repo.import_dependencies(
            project_id=project.id,
            service_name=service_name,
            filename=filename,
            sha256_hash=sha256_hash,
            parsed_graph=parsed_graph,
            secondary_filename=secondary_filename,
            ecosystem=cap.id,
            import_method=method.id,
        )
    except HTTPException as exc:
        job.status = JobStatus.FAILED
        job.stage = f"Failed: {exc.detail}"
        job.error_summary = str(exc.detail)
        job.errors = [str(exc.detail)]
        job.completed_at = int(datetime.now(timezone.utc).timestamp())
        job.duration_ms = round((time.time() - t0) * 1000, 2)
        job.retry_eligible = True
        job_repo.upsert_job(job)
        raise
    except Exception as exc:
        job.status = JobStatus.FAILED
        job.stage = "Persistence failed: Failed to persist dependency graph in database."
        job.error_summary = "Failed to persist dependency graph in database."
        job.errors = ["Failed to persist dependency graph in database."]
        job.completed_at = int(datetime.now(timezone.utc).timestamp())
        job.duration_ms = round((time.time() - t0) * 1000, 2)
        job.retry_eligible = True
        job_repo.upsert_job(job)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist dependency graph in database.",
        ) from exc

    duration_ms = round((time.time() - t0) * 1000, 2)
    job.total_items = len(parsed_graph.packages)
    job.processed_items = len(parsed_graph.packages)
    job.percentage = 100.0
    job.discovered_items = len(parsed_graph.packages)
    job.created_items = summary.packages_created
    job.reused_items = summary.packages_reused
    job.skipped_items = summary.skipped_entries
    job.warnings = summary.warnings
    job.errors = summary.errors
    job.status = JobStatus.SUCCEEDED if summary.status == "completed" else JobStatus.PARTIAL
    job.stage = (
        "Dependency import completed successfully"
        if job.status == JobStatus.SUCCEEDED
        else "Dependency import completed with warnings"
    )
    job.completed_at = int(datetime.now(timezone.utc).timestamp())
    job.duration_ms = duration_ms
    job.retry_eligible = (job.status == JobStatus.PARTIAL)
    job_repo.upsert_job(job)
    summary.job_id = job.id

    return summary


@router.post(
    "/{project_id}/advisories/import",
    response_model=OsvImportSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Import OSV advisories for project packages",
)
async def import_project_advisories(
    project_id: str,
    request: Request,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    advisory_service: OsvService = Depends(get_osv_service),
) -> OsvImportSummaryResponse:
    """Retrieve vulnerability advisories from OSV for packages in the project and persist in FalkorDB."""
    force_refresh = request.query_params.get("force_refresh", "false").lower() in ("true", "1", "yes")
    user_identity = getattr(current_user, "email", None) or str(current_user.id)

    try:
        summary = await advisory_service.import_project_advisories(
            project.id,
            force_refresh=force_refresh,
            initiated_by=user_identity,
        )
        return summary
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to import OSV advisories: {str(exc)}",
        ) from exc


@router.get(
    "/{project_id}/advisories",
    response_model=list[ProjectAdvisoryResponse],
    status_code=status.HTTP_200_OK,
    summary="List detected advisories for a project",
)
async def list_project_advisories(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    advisory_repo: IAdvisoryRepository = Depends(get_advisory_repository),
) -> list[ProjectAdvisoryResponse]:
    """Retrieve all vulnerability advisories currently linked to package versions in the project."""
    try:
        records = advisory_repo.get_project_advisories(project.id)
        return [ProjectAdvisoryResponse(**r) for r in records]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve project advisories from database.",
        ) from exc


@router.post(
    "/{project_id}/vulnerabilities/match",
    response_model=ProjectMatchResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate and persist ecosystem-aware vulnerability matching",
)
async def match_project_vulnerabilities(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    matching_service: VersionMatchingService = Depends(get_version_matching_service),
) -> ProjectMatchResponse:
    """Evaluate all package-advisory pairs for a project using ecosystem-aware version semantics.
    
    Idempotently updates AFFECTS relationships in FalkorDB with explainable match reasons.
    """
    user_identity = getattr(current_user, "email", None) or str(current_user.id)
    try:
        match_result = matching_service.match_project_vulnerabilities(
            project.id,
            initiated_by=user_identity,
        )
        try:
            decision_service = get_decision_service()
            decision_service.detect_changes_for_project(project.id)
        except Exception:
            pass  # Do not block matching if change detection fails
        return match_result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute version matching: {str(exc)}",
        ) from exc


@router.get(
    "/{project_id}/vulnerabilities",
    response_model=list[VulnerabilityFindingResponse],
    status_code=status.HTTP_200_OK,
    summary="List confirmed vulnerability findings with match reasons",
)
async def get_project_vulnerabilities(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    matching_service: VersionMatchingService = Depends(get_version_matching_service),
) -> list[VulnerabilityFindingResponse]:
    """Retrieve confirmed vulnerability findings with ecosystem-aware match reasons and fixed versions."""
    try:
        return matching_service.get_project_findings(project.id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve vulnerability findings from database.",
        ) from exc


@router.get(
    "/{project_id}/services",
    response_model=list[ProjectServiceResponse],
    status_code=status.HTTP_200_OK,
    summary="List all distinct services for a project",
)
async def list_project_services(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
) -> list[ProjectServiceResponse]:
    """Retrieve distinct services associated with the project."""
    try:
        raw_services = repo.list_project_services(project.id)
        return [ProjectServiceResponse(id=s["id"], name=s["name"]) for s in raw_services]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve project services from database.",
        ) from exc


@router.get(
    "/{project_id}/findings",
    response_model=FindingListResponse,
    status_code=status.HTTP_200_OK,
    summary="List confirmed vulnerability findings with path depth and triage status",
)
async def list_project_findings(
    project_id: str,
    page: int = Query(default=1, ge=1, description="Page number, 1-indexed"),
    page_size: int = Query(default=25, ge=1, le=100, description="Items per page (max 100)"),
    priority: str | None = Query(default=None, description="Filter by priority band"),
    service_id: str | None = Query(default=None, description="Filter by service ID"),
    status: str | None = Query(default=None, description="Filter by triage status"),
    search: str | None = Query(default=None, description="Search advisory ID or package name"),
    sort_by: str | None = Query(default=None, description="Sort order ('priority' for ranked bands with tie-breakers, or default)"),
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
) -> FindingListResponse:
    """Retrieve paginated, project-scoped vulnerability findings with evidence, priority reasons, and path depth."""
    try:
        offset = (page - 1) * page_size
        items, total = repo.get_project_findings(
            project_id=project.id,
            service_id=service_id,
            search=search,
            priority=priority,
            status=status,
            limit=page_size,
            offset=offset,
            sort_by=sort_by,
        )
        total_pages = math.ceil(total / page_size) if total > 0 else 0
        return FindingListResponse(
            items=[FindingItemResponse(**item) for item in items],
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve project findings from database.",
        ) from exc


@router.get(
    "/{project_id}/findings/summary",
    response_model=FindingSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated finding counts for summary cards",
)
async def get_project_findings_summary(
    project_id: str,
    priority: str | None = Query(default=None, description="Filter by priority band"),
    service_id: str | None = Query(default=None, description="Filter by service ID"),
    triage_status: str | None = Query(default=None, alias="status", description="Filter by triage status"),
    search: str | None = Query(default=None, description="Search advisory ID or package name"),
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
) -> FindingSummaryResponse:
    """Retrieve aggregated finding metrics for the project and active filters."""
    try:
        summary_counts = repo.get_project_findings_summary(
            project_id=project.id,
            service_id=service_id,
            search=search,
            priority=priority,
            status=triage_status,
        )
        return FindingSummaryResponse(
            project_id=project.id,
            advisory_matches=summary_counts["advisory_matches"],
            findings_with_path=summary_counts["findings_with_path"],
            findings_without_path=summary_counts["findings_without_path"],
            findings_needing_decision=summary_counts["findings_needing_decision"],
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve project findings summary from database.",
        ) from exc


@router.get(
    "/{project_id}/data-quality",
    response_model=ProjectDataQualityResponse,
    status_code=status.HTTP_200_OK,
    summary="Get project-scoped data quality warnings",
)
async def get_project_data_quality(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    dq_service: DataQualityService = Depends(get_data_quality_service),
) -> ProjectDataQualityResponse:
    """Evaluate and return data quality warnings (missing topology, stale advisories, partial imports)."""
    try:
        warnings = dq_service.evaluate_project_warnings(project.id)
        now = int(datetime.now(timezone.utc).timestamp())
        return ProjectDataQualityResponse(
            project_id=project.id,
            has_warnings=len(warnings) > 0,
            warning_count=len(warnings),
            warnings=warnings,
            evaluated_at=now,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to evaluate project data quality warnings.",
        ) from exc


@router.get(
    "/{project_id}/findings/{finding_id}",
    response_model=FindingDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detailed evidence and advisory information for a specific finding",
)
async def get_project_finding_detail(
    project_id: str,
    finding_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
    dq_service: DataQualityService = Depends(get_data_quality_service),
) -> FindingDetailResponse:
    """Retrieve evidence, version matching justification, and advisory details for a single finding."""
    try:
        finding = repo.get_project_finding_detail(project.id, finding_id)
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding_id}' not found in project '{project.id}'.",
            )
        finding_dict = dict(finding)
        finding_dict["warnings"] = dq_service.evaluate_finding_warnings(project.id, finding_dict)
        return FindingDetailResponse(**finding_dict)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve finding detail from database.",
        ) from exc


@router.post(
    "/{project_id}/findings/{finding_id}/decision",
    response_model=TriageDecisionResponse,
    status_code=status.HTTP_200_OK,
    summary="Record or update human triage decision with baseline evidence capture (US-402)",
)
async def record_finding_decision(
    project_id: str,
    finding_id: str,
    request: TriageDecisionRequest,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    decision_service: DecisionService = Depends(get_decision_service),
) -> TriageDecisionResponse:
    """Record a triage decision ('not_affected', 'fixed', 'affected', etc.) for a finding.
    
    Captures baseline evidence snapshot and stores audit metadata. If 'not_affected' is chosen,
    a justification (>= 10 characters) is required.
    """
    user_identity = getattr(current_user, "email", None) or str(current_user.id)
    try:
        record = decision_service.record_decision(
            project_id=project.id,
            finding_id=finding_id,
            status=request.status,
            triaged_by=user_identity,
            justification=request.justification,
        )
        return TriageDecisionResponse(**record.model_dump())
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        ) from val_err
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record triage decision: {str(exc)}",
        ) from exc


@router.post(
    "/{project_id}/findings/{finding_id}/review",
    response_model=TriageDecisionResponse,
    status_code=status.HTTP_200_OK,
    summary="Review and acknowledge or update a finding flagged for review (US-402)",
)
async def review_finding_decision(
    project_id: str,
    finding_id: str,
    request: ReviewDecisionRequest,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    decision_service: DecisionService = Depends(get_decision_service),
) -> TriageDecisionResponse:
    """Review a finding flagged 'needs review'.
    
    Clears the review_required flag, records review audit metadata, and advances baseline snapshot.
    """
    user_identity = getattr(current_user, "email", None) or str(current_user.id)
    try:
        record = decision_service.review_decision(
            project_id=project.id,
            finding_id=finding_id,
            reviewed_by=user_identity,
            action=request.action,
            new_status=request.new_status,
            new_justification=request.new_justification,
            notes=request.notes,
        )
        return TriageDecisionResponse(**record.model_dump())
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        ) from val_err
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to review decision: {str(exc)}",
        ) from exc


@router.get(
    "/{project_id}/findings/{finding_id}/decision",
    response_model=ChangeComparisonResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current decision, baseline snapshot, and evidence comparison (US-402)",
)
async def get_finding_decision(
    project_id: str,
    finding_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    decision_service: DecisionService = Depends(get_decision_service),
) -> ChangeComparisonResponse:
    """Inspect the baseline snapshot and compare current evidence to detect changes for a finding."""
    try:
        comparison = decision_service.detect_changes_for_finding(
            project_id=project.id,
            finding_id=finding_id,
        )
        return ChangeComparisonResponse(**comparison.model_dump())
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get finding decision: {str(exc)}",
        ) from exc


@router.post(
    "/{project_id}/decisions/detect-changes",
    summary="Detect changes across all project findings with prior decisions (US-402)",
)
async def detect_project_decision_changes(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    decision_service: DecisionService = Depends(get_decision_service),
) -> dict[str, Any]:
    """Evaluate change detection across all settled findings in the project."""
    try:
        results = decision_service.detect_changes_for_project(project.id)
        flagged_count = sum(1 for r in results if r.review_required)
        return {
            "project_id": project.id,
            "evaluated_count": len(results),
            "flagged_count": flagged_count,
            "results": [r.model_dump() for r in results],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to detect project decision changes: {str(exc)}",
        ) from exc


@router.get(
    "/{project_id}/findings/{finding_id}/paths",
    response_model=FindingPathsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get shortest bounded dependency paths from service to affected package",
)
async def get_project_finding_paths(
    project_id: str,
    finding_id: str,
    max_depth: int = Query(default=8, ge=1, le=15, description="Maximum dependency path depth"),
    limit: int = Query(default=5, ge=1, le=20, description="Maximum number of shortest paths to return"),
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
    dq_service: DataQualityService = Depends(get_data_quality_service),
) -> FindingPathsResponse:
    """Retrieve shortest dependency paths from root service to the affected package version."""
    try:
        finding = repo.get_project_finding_detail(project.id, finding_id)
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding_id}' not found in project '{project.id}'.",
            )

        service_id = finding["service_id"]
        service_name = finding["service_name"]
        package_version_id = finding["package_version_id"]
        package_name = finding["package_name"]
        package_version = finding["package_version"]
        advisory_id = finding["advisory_id"]

        paths, is_truncated, total_found = repo.get_finding_dependency_paths(
            project_id=project.id,
            service_id=service_id,
            package_version_id=package_version_id,
            max_depth=max_depth,
            limit=limit,
        )

        now = int(datetime.now(timezone.utc).timestamp())
        has_path = len(paths) > 0

        # AC-1: Honest no-path message with depth and scope bounds
        no_path_message = None
        if not has_path:
            no_path_message = (
                f"No dependency path was found from service '{service_name}' to package '{package_name}' "
                f"within the maximum traversal depth of {max_depth} hops. 'No path found' does not guarantee safety: "
                "the target package version is present in the project's dependency manifest and may still be reached "
                "via dynamically resolved dependencies, undeclared calls, or out-of-scope services."
            )

        warnings = dq_service.evaluate_finding_warnings(project.id, finding)
        exp_items, _, _, _ = repo.get_project_exposure_paths(project.id, finding_id=finding["id"], limit=1)
        exposure_path = exp_items[0] if exp_items else None

        return FindingPathsResponse(
            project_id=project.id,
            finding_id=finding["id"],
            service_id=service_id,
            service_name=service_name,
            advisory_id=advisory_id,
            package_name=package_name,
            package_version=package_version,
            package_version_id=package_version_id,
            paths=paths,
            total_paths_found=total_found,
            max_depth_applied=max_depth,
            limit_applied=limit,
            is_truncated=is_truncated,
            has_path=has_path,
            evaluated_at=now,
            no_path_message=no_path_message,
            warnings=warnings,
            exposure_path=exposure_path,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dependency paths from database.",
        ) from exc


@router.get(
    "/{project_id}/exposure-paths",
    response_model=ProjectExposurePathsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get architectural exposure paths through service and dependency topology (US-205)",
)
async def get_project_exposure_paths(
    project_id: str,
    finding_id: str | None = Query(default=None, description="Optional finding filter"),
    service_id: str | None = Query(default=None, description="Optional service filter"),
    limit: int = Query(default=20, ge=1, le=50, description="Maximum number of exposure paths to return"),
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
    dq_service: DataQualityService = Depends(get_data_quality_service),
) -> ProjectExposurePathsResponse:
    """Traverse service-to-service calls and package dependencies to analyze end-to-end architectural exposure (US-205)."""
    try:
        items, unsupported_ecosystems, topo_status, has_internet = repo.get_project_exposure_paths(
            project_id=project.id,
            finding_id=finding_id,
            service_id=service_id,
            limit=limit,
        )
        now = int(datetime.now(timezone.utc).timestamp())
        warnings = dq_service.evaluate_project_warnings(project.id)

        return ProjectExposurePathsResponse(
            project_id=project.id,
            topology_status=topo_status,
            has_internet_exposure=has_internet,
            total_exposure_paths=len(items),
            items=items,
            unsupported_ecosystems=unsupported_ecosystems,
            warnings=warnings,
            evaluated_at=now,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve exposure paths from database.",
        ) from exc


@router.get(
    "/{project_id}/findings/{finding_id}/exposure-paths",
    response_model=ProjectExposurePathsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get architectural exposure path for a specific finding (US-205)",
)
async def get_single_finding_exposure_paths(
    project_id: str,
    finding_id: str,
    limit: int = Query(default=5, ge=1, le=20, description="Maximum number of exposure paths to return"),
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
    dq_service: DataQualityService = Depends(get_data_quality_service),
) -> ProjectExposurePathsResponse:
    """Retrieve end-to-end architectural exposure path for a single finding (US-205)."""
    try:
        finding = repo.get_project_finding_detail(project.id, finding_id)
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding_id}' not found in project '{project.id}'.",
            )
        items, unsupported_ecosystems, topo_status, has_internet = repo.get_project_exposure_paths(
            project_id=project.id,
            finding_id=finding["id"],
            limit=limit,
        )
        now = int(datetime.now(timezone.utc).timestamp())
        warnings = dq_service.evaluate_finding_warnings(project.id, finding)

        return ProjectExposurePathsResponse(
            project_id=project.id,
            topology_status=topo_status,
            has_internet_exposure=has_internet,
            total_exposure_paths=len(items),
            items=items,
            unsupported_ecosystems=unsupported_ecosystems,
            warnings=warnings,
            evaluated_at=now,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve exposure paths from database.",
        ) from exc


@router.get(
    "/{project_id}/findings/{finding_id}/upgrade-candidates",
    response_model=UpgradeCandidatesResponse,
    status_code=status.HTTP_200_OK,
    summary="Get suggested upgrade targets and compatibility caveats for a finding (US-401)",
)
async def get_finding_upgrade_candidates(
    project_id: str,
    finding_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    candidates_service: UpgradeCandidatesService = Depends(get_upgrade_candidates_service),
) -> UpgradeCandidatesResponse:
    """Retrieve suggested upgrade candidates derived strictly from advisory fixed versions with caveats."""
    try:
        candidates = candidates_service.get_finding_upgrade_candidates(project.id, finding_id)
        if not candidates:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding_id}' not found in project '{project.id}'.",
            )
        return candidates
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to evaluate upgrade candidates from database.",
        ) from exc


@router.get(
    "/{project_id}/upgrade-candidates",
    response_model=ProjectUpgradeCandidatesResponse,
    status_code=status.HTTP_200_OK,
    summary="List upgrade candidate evaluations for all project findings (US-401 / US-501)",
)
async def get_project_upgrade_candidates(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    candidates_service: UpgradeCandidatesService = Depends(get_upgrade_candidates_service),
) -> ProjectUpgradeCandidatesResponse:
    """Retrieve project-wide upgrade candidate evaluations with SemVer differentials and compatibility caveats."""
    try:
        return candidates_service.get_project_upgrade_candidates(project.id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to evaluate project upgrade candidates from database.",
        ) from exc

# =====================================================================
# US-501 / US-502: Fix Simulation Endpoints
# =====================================================================


@router.post(
    "/{project_id}/simulations",
    response_model=SimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate package upgrade on an in-memory graph overlay (US-501)",
)
async def simulate_fix(
    project_id: str,
    request: SimulationRequest,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    simulation_service: FixSimulationService = Depends(get_fix_simulation_service),
) -> SimulationResponse:
    """Run a non-mutating in-memory graph overlay simulation for a proposed package upgrade."""
    try:
        return simulation_service.simulate_fix(project.id, request)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute fix simulation: {str(exc)}",
        ) from exc


@router.get(
    "/{project_id}/simulations",
    response_model=SimulationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List recent fix simulations for project (US-501)",
)
async def list_simulations(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    simulation_service: FixSimulationService = Depends(get_fix_simulation_service),
) -> SimulationListResponse:
    """Retrieve recent in-memory fix simulations performed for this project."""
    try:
        return simulation_service.list_simulations(project.id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve project simulations.",
        ) from exc


@router.get(
    "/{project_id}/simulations/{simulation_id}",
    response_model=SimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get details of a specific simulation run (US-501)",
)
async def get_simulation(
    project_id: str,
    simulation_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    simulation_service: FixSimulationService = Depends(get_fix_simulation_service),
) -> SimulationResponse:
    """Retrieve details and checklist for a specific simulation run."""
    sim = simulation_service.get_simulation(project.id, simulation_id)
    if not sim:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation '{simulation_id}' not found for project '{project.id}'.",
        )
    return sim


# =====================================================================
# US-503 / US-504: GitHub Issue Remediation Endpoints
# =====================================================================


@router.get(
    "/{project_id}/github/status",
    response_model=GitHubIntegrationStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get GitHub integration configuration status (US-503 / US-506)",
)
async def get_github_status(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubIntegrationStatusResponse:
    """Retrieve GitHub integration configuration status and default target repository."""
    return github_service.get_status(project.id)


@router.get(
    "/{project_id}/github/config",
    response_model=GitHubConfigResponse,
    status_code=status.HTTP_200_OK,
    summary="Get project GitHub integration configuration (US-506)",
)
async def get_project_github_config(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubConfigResponse:
    """Retrieve current non-sensitive GitHub configuration for this workspace."""
    return github_service.get_config(project.id)


@router.put(
    "/{project_id}/github/config",
    response_model=GitHubConfigResponse,
    status_code=status.HTTP_200_OK,
    summary="Update project GitHub integration configuration (US-506)",
)
async def update_project_github_config(
    project_id: str,
    body: GitHubConfigUpdateRequest,
    current_user: UserResponse = Depends(require_admin),
    project: ProjectRecord = Depends(get_valid_project),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubConfigResponse:
    """Update and validate target repository configuration for this project (admin only)."""
    return await github_service.update_config(
        owner=body.owner,
        repo=body.repo,
        token=body.token,
        api_base_url=body.api_base_url,
        project_id=project.id,
        validate_before_save=body.validate_before_save,
        current_user=current_user,
    )


@router.post(
    "/{project_id}/github/validate",
    response_model=GitHubValidationResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate project GitHub target repository access (US-506)",
)
async def validate_project_github_config(
    project_id: str,
    body: GitHubConfigValidateRequest,
    current_user: UserResponse = Depends(require_admin),
    project: ProjectRecord = Depends(get_valid_project),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubValidationResultResponse:
    """Test repository access and write permissions against GitHub REST API (admin only)."""
    return await github_service.validate_target_repo_access(
        owner=body.owner,
        repo=body.repo,
        token=body.token,
        project_id=project.id,
    )



@router.post(
    "/{project_id}/findings/{finding_id}/github-issues/preview",
    response_model=GitHubIssuePreviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate structured GitHub issue preview with plan hash (US-503)",
)
async def preview_github_issue(
    project_id: str,
    finding_id: str,
    request: GitHubIssuePreviewRequest,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubIssuePreviewResponse:
    """Generate structured markdown issue preview and cryptographic plan hash for review (US-503)."""
    return github_service.generate_preview(project.id, finding_id, request)


@router.post(
    "/{project_id}/findings/{finding_id}/github-issues",
    response_model=GitHubIssueRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve and create real GitHub issue via REST API (US-504)",
)
async def create_github_issue(
    project_id: str,
    finding_id: str,
    request: GitHubIssueCreateRequest,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubIssueRecordResponse:
    """Validate approved plan hash, enforce human gating, and create GitHub issue (US-504)."""
    return await github_service.create_issue(project.id, finding_id, request, current_user)


@router.get(
    "/{project_id}/github-issues",
    response_model=GitHubIssueListResponse,
    status_code=status.HTTP_200_OK,
    summary="List remediation issues created for project (US-505)",
)
async def list_project_github_issues(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    github_service: GitHubService = Depends(get_github_service),
) -> GitHubIssueListResponse:
    """Retrieve action history of GitHub remediation issues filed for this project."""
    return github_service.list_project_issues(project.id)


@router.get(
    "/{project_id}/packages",
    response_model=list[PackageVersionResponse],
    status_code=status.HTTP_200_OK,
    summary="List all package versions imported for a project",
)
async def list_project_packages(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    advisory_repo: IAdvisoryRepository = Depends(get_advisory_repository),
) -> list[PackageVersionResponse]:
    """Retrieve distinct package versions reachable from services belonging to a project."""
    try:
        packages = advisory_repo.get_project_package_versions(project.id)
        return [
            PackageVersionResponse(
                id=p.id,
                name=p.name,
                version=p.version,
                ecosystem=p.ecosystem,
                purl=p.purl,
            )
            for p in packages
        ]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve project packages from database.",
        ) from exc


# =====================================================================
# US-105: Ingestion Jobs and History Endpoints
# =====================================================================


@router.get(
    "/{project_id}/jobs",
    response_model=IngestionJobListResponse,
    status_code=status.HTTP_200_OK,
    summary="List ingestion job history for a project",
)
async def list_project_jobs(
    project_id: str,
    page: int = 1,
    page_size: int = 20,
    status: str | None = None,
    job_type: str | None = None,
    service_name: str | None = None,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    job_repo: IIngestionJobRepository = Depends(get_job_repository),
) -> IngestionJobListResponse:
    """Retrieve historical ingestion jobs for the project with filtering and pagination."""
    if page < 1:
        raise HTTPException(status_code=422, detail="Page must be greater than or equal to 1.")
    if page_size < 1 or page_size > 100:
        raise HTTPException(status_code=422, detail="Page size must be between 1 and 100.")

    offset = (page - 1) * page_size
    records, total, summary_stats = job_repo.list_jobs(
        project_id=project.id,
        status=status,
        job_type=job_type,
        service_name=service_name,
        limit=page_size,
        offset=offset,
    )

    items = [
        IngestionJobResponse(
            id=r.id,
            project_id=r.project_id,
            job_type=r.job_type,
            status=r.status,
            stage=r.stage,
            service_id=r.service_id,
            service_name=r.service_name,
            processed_items=r.processed_items,
            total_items=r.total_items,
            percentage=r.percentage,
            discovered_items=r.discovered_items,
            created_items=r.created_items,
            updated_items=r.updated_items,
            reused_items=r.reused_items,
            skipped_items=r.skipped_items,
            failed_items=r.failed_items,
            error_summary=r.error_summary,
            errors=r.errors,
            warnings=r.warnings,
            retry_eligible=r.retry_eligible,
            retry_of_job_id=r.retry_of_job_id,
            created_at=r.created_at,
            started_at=r.started_at,
            completed_at=r.completed_at,
            duration_ms=r.duration_ms,
            initiated_by=r.initiated_by,
            filename=r.filename,
            secondary_filename=r.secondary_filename,
            sha256_hash=r.sha256_hash,
            ecosystem=r.ecosystem,
            import_method=r.import_method,
            fidelity=r.fidelity,
        )
        for r in records
    ]

    total_pages = math.ceil(total / page_size) if total > 0 else 1

    return IngestionJobListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        summary_stats=IngestionJobSummaryStats(**summary_stats),
    )


@router.get(
    "/{project_id}/jobs/{job_id}",
    response_model=IngestionJobResponse,
    status_code=status.HTTP_200_OK,
    summary="Get ingestion job details by ID",
)
async def get_project_job(
    project_id: str,
    job_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    job_repo: IIngestionJobRepository = Depends(get_job_repository),
) -> IngestionJobResponse:
    """Retrieve detailed state, progress, and results for a single ingestion job."""
    job = job_repo.get_job(project_id=project.id, job_id=job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Ingestion job '{job_id}' not found for project '{project.id}'.",
        )

    return IngestionJobResponse(
        id=job.id,
        project_id=job.project_id,
        job_type=job.job_type,
        status=job.status,
        stage=job.stage,
        service_id=job.service_id,
        service_name=job.service_name,
        processed_items=job.processed_items,
        total_items=job.total_items,
        percentage=job.percentage,
        discovered_items=job.discovered_items,
        created_items=job.created_items,
        updated_items=job.updated_items,
        reused_items=job.reused_items,
        skipped_items=job.skipped_items,
        failed_items=job.failed_items,
        error_summary=job.error_summary,
        errors=job.errors,
        warnings=job.warnings,
        retry_eligible=job.retry_eligible,
        retry_of_job_id=job.retry_of_job_id,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        duration_ms=job.duration_ms,
        initiated_by=job.initiated_by,
        filename=job.filename,
        secondary_filename=job.secondary_filename,
        sha256_hash=job.sha256_hash,
        ecosystem=job.ecosystem,
        import_method=job.import_method,
        fidelity=job.fidelity,
    )


@router.post(
    "/{project_id}/jobs/{job_id}/retry",
    response_model=JobRetryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retry an eligible failed or partial ingestion job",
)
async def retry_project_job(
    project_id: str,
    job_id: str,
    current_user: UserResponse = Depends(require_auth),
    project: ProjectRecord = Depends(get_valid_project),
    job_repo: IIngestionJobRepository = Depends(get_job_repository),
    advisory_service: OsvService = Depends(get_osv_service),
    matching_service: VersionMatchingService = Depends(get_version_matching_service),
) -> JobRetryResponse:
    """Retry an eligible failed or partial ingestion job, creating a new linked run record."""
    original_job = job_repo.get_job(project_id=project.id, job_id=job_id)
    if not original_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Ingestion job '{job_id}' not found for project '{project.id}'.",
        )

    if original_job.status not in (JobStatus.FAILED, JobStatus.PARTIAL):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot retry job with status '{original_job.status}'. Only failed or partial jobs are eligible for retry.",
        )

    if not original_job.retry_eligible:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Job is not eligible for retry.",
        )

    user_identity = getattr(current_user, "email", None) or str(current_user.id)
    new_job_id = str(uuid.uuid4())
    now_ts = int(datetime.now(timezone.utc).timestamp())

    new_job = IngestionJobRecord(
        id=new_job_id,
        project_id=project.id,
        service_id=original_job.service_id,
        service_name=original_job.service_name,
        job_type=original_job.job_type,
        status=JobStatus.QUEUED,
        stage="Queued for retry",
        created_at=now_ts,
        initiated_by=user_identity,
        filename=original_job.filename,
        secondary_filename=original_job.secondary_filename,
        sha256_hash=original_job.sha256_hash,
        ecosystem=original_job.ecosystem,
        import_method=original_job.import_method,
        fidelity=original_job.fidelity,
        retry_of_job_id=original_job.id,
    )
    job_repo.upsert_job(new_job)

    if original_job.job_type == JobType.OSV_SYNC:
        await advisory_service.import_project_advisories(
            project.id,
            force_refresh=True,
            initiated_by=user_identity,
            job_id=new_job_id,
        )
    elif original_job.job_type == JobType.VERSION_MATCHING:
        matching_service.match_project_vulnerabilities(
            project.id,
            initiated_by=user_identity,
            job_id=new_job_id,
        )
    elif original_job.job_type == JobType.DEPENDENCY_IMPORT:
        # Dependency lockfiles cannot be retried without re-uploading the file
        new_job.status = JobStatus.FAILED
        new_job.stage = "Retry failed: dependency file must be re-uploaded."
        new_job.error_summary = "Lockfile import retry requires re-uploading the dependency file."
        new_job.completed_at = now_ts
        job_repo.upsert_job(new_job)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Lockfile import retry requires re-uploading the dependency file.",
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported job type '{original_job.job_type}' for retry.",
        )

    executed_job = job_repo.get_job(project.id, new_job_id) or new_job

    return JobRetryResponse(
        message=f"Job {job_id} successfully retried as {new_job_id}.",
        original_job_id=original_job.id,
        new_job=IngestionJobResponse(
            id=executed_job.id,
            project_id=executed_job.project_id,
            job_type=executed_job.job_type,
            status=executed_job.status,
            stage=executed_job.stage,
            service_id=executed_job.service_id,
            service_name=executed_job.service_name,
            processed_items=executed_job.processed_items,
            total_items=executed_job.total_items,
            percentage=executed_job.percentage,
            discovered_items=executed_job.discovered_items,
            created_items=executed_job.created_items,
            updated_items=executed_job.updated_items,
            reused_items=executed_job.reused_items,
            skipped_items=executed_job.skipped_items,
            failed_items=executed_job.failed_items,
            error_summary=executed_job.error_summary,
            errors=executed_job.errors,
            warnings=executed_job.warnings,
            retry_eligible=executed_job.retry_eligible,
            retry_of_job_id=executed_job.retry_of_job_id,
            created_at=executed_job.created_at,
            started_at=executed_job.started_at,
            completed_at=executed_job.completed_at,
            duration_ms=executed_job.duration_ms,
            initiated_by=executed_job.initiated_by,
            filename=executed_job.filename,
            secondary_filename=executed_job.secondary_filename,
            sha256_hash=executed_job.sha256_hash,
            ecosystem=executed_job.ecosystem,
            import_method=executed_job.import_method,
            fidelity=executed_job.fidelity,
        ),
    )



