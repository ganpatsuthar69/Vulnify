import asyncio
import email
import hashlib
from fastapi import APIRouter, Depends, HTTPException, Request, status

from vulnify.config import Settings, get_settings
from vulnify.dependencies import get_valid_project, require_auth
from vulnify.graph.advisory_repository import IAdvisoryRepository, get_advisory_repository
from vulnify.graph.dependency_repository import IDependencyRepository, get_dependency_repository
from vulnify.graph.project_repository import (
    IProjectRepository,
    ProjectRecord,
    get_project_repository,
)
from vulnify.osv.service import OsvService, get_osv_service
from vulnify.parsers.models import LockfileParseError
from vulnify.parsers.npm import parse_npm_lockfile
from vulnify.schemas import (
    SERVICE_NAME_REGEX,
    SUPPORTED_ECOSYSTEMS,
    ImportSummaryResponse,
    OsvImportSummaryResponse,
    ProjectAdvisoryResponse,
    ProjectCreateRequest,
    ProjectMatchResponse,
    ProjectResponse,
    UserResponse,
    VulnerabilityFindingResponse,
)
from vulnify.version_matching.service import (
    VersionMatchingService,
    get_version_matching_service,
)

router = APIRouter(prefix="/api/projects", tags=["projects"])

# Async lock to ensure serial execution of project name check-and-create across concurrent requests
_create_project_lock = asyncio.Lock()


def _extract_multipart(body: bytes, content_type: str) -> tuple[str | None, str | None, bytes | None]:
    """Parse multipart/form-data using standard library email parser."""
    msg = email.message_from_bytes(f"Content-Type: {content_type}\r\n\r\n".encode("latin-1") + body)
    service_name = None
    filename = None
    file_bytes = None

    if msg.is_multipart():
        for part in msg.get_payload():
            cd_name = part.get_param("name", header="content-disposition")
            if cd_name == "service_name":
                payload = part.get_payload(decode=True)
                if payload:
                    service_name = payload.decode("utf-8", errors="replace").strip()
            elif cd_name == "file":
                filename = part.get_filename() or "package-lock.json"
                file_bytes = part.get_payload(decode=True)
    return service_name, filename, file_bytes


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
        records = repo.list_projects()
        return [
            ProjectResponse(
                id=r.id,
                name=r.name,
                ecosystem=r.ecosystem,
                description=r.description,
                created_at=r.created_at,
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
    )


@router.get(
    "/ecosystems",
    summary="List supported ecosystems",
)
async def get_supported_ecosystems(
    current_user: UserResponse = Depends(require_auth),
) -> dict[str, list[str]]:
    """Return the list of package ecosystems supported by the system."""
    return {"supported_ecosystems": list(SUPPORTED_ECOSYSTEMS)}


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    status_code=status.HTTP_200_OK,
    summary="Get project by ID",
)
async def get_project(
    project_id: str,
    current_user: UserResponse = Depends(require_auth),
    repo: IProjectRepository = Depends(get_project_repository),
) -> ProjectResponse:
    """Retrieve details of a specific project by its stable identifier."""
    record = repo.get_by_id(project_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found.",
        )
    return ProjectResponse(
        id=record.id,
        name=record.name,
        ecosystem=record.ecosystem,
        description=record.description,
        created_at=record.created_at,
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

    if "multipart/form-data" in content_type:
        service_name, filename, file_bytes = _extract_multipart(body, raw_content_type)
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

    # 6. Validate lockfile format against project ecosystem
    project_ecosystem = project.ecosystem.strip()
    if project_ecosystem.lower() != "npm":
        raise HTTPException(
            status_code=422,
            detail=f"Project ecosystem '{project_ecosystem}' is not currently supported for lockfile import. Only npm projects are supported.",
        )

    lower_fn = filename.lower()
    if not (lower_fn == "package-lock.json" or lower_fn.endswith(".json")):
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported lockfile format '{filename}'. Supported format for npm projects is 'package-lock.json'.",
        )

    # 7. Compute SHA-256 hash
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    # 8. Parse lockfile without code execution
    try:
        parsed_graph = parse_npm_lockfile(file_bytes, filename=filename)
    except LockfileParseError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="Failed to parse lockfile contents.",
        ) from exc

    # 9. Persist into FalkorDB
    try:
        summary = dep_repo.import_dependencies(
            project_id=project.id,
            service_name=service_name,
            filename=filename,
            sha256_hash=sha256_hash,
            parsed_graph=parsed_graph,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist dependency graph in database.",
        ) from exc

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

    try:
        summary = await advisory_service.import_project_advisories(project.id, force_refresh=force_refresh)
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
    try:
        return matching_service.match_project_vulnerabilities(project.id)
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


