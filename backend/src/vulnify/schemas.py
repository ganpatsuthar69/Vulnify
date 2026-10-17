"""Pydantic v2 data models for Vulnify user management, authentication, and health."""

import re
from typing import Literal
from pydantic import BaseModel, Field, field_validator

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="User full name")
    email: str = Field(..., min_length=3, max_length=255, description="Unique user email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (minimum 8 characters)",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Name cannot be empty or whitespace only.")
        return cleaned

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format.")
        return cleaned


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255, description="Registered user email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format.")
        return cleaned


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: Literal["user", "admin"]


class RoleUpdateRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    role: Literal["user", "admin"]

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format.")
        return cleaned


class HealthResponse(BaseModel):
    status: str = "healthy"


from vulnify.parsers.registry import (
    EcosystemCapabilitiesResponse,
    EcosystemCapability,
    ImportFieldDefinition,
    ImportMethodCapability,
    get_ecosystem_registry,
    get_supported_ecosystem_ids,
)

SUPPORTED_ECOSYSTEMS: tuple[str, ...] = ("npm", "PyPI", "Cargo", "Go")
SupportedEcosystem = str


class ProjectCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Project name")
    ecosystem: str = Field(..., description="Package ecosystem (e.g. npm, PyPI, Cargo, Go)")
    description: str | None = Field(default=None, max_length=500, description="Optional project description")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Project name cannot be empty or whitespace only.")
        return cleaned

    @field_validator("ecosystem")
    @classmethod
    def validate_ecosystem(cls, v: str) -> str:
        cleaned = v.strip()
        registry = get_ecosystem_registry()
        matched = registry.get_canonical_ecosystem_name(cleaned)
        if not matched:
            supported_str = ", ".join(registry.get_supported_ecosystem_ids())
            raise ValueError(
                f"Unsupported ecosystem '{cleaned}'. Supported ecosystems are: {supported_str}."
            )
        return matched

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str | None) -> str | None:
        if v is None:
            return None
        cleaned = v.strip()
        return cleaned if cleaned else None


class ProjectResponse(BaseModel):
    id: str
    name: str
    ecosystem: str
    description: str | None = None
    created_at: int



class ErrorResponse(BaseModel):
    code: str = Field(..., description="Stable, machine-readable error identifier")
    message: str = Field(..., description="Safe, human-readable error message")
    request_id: str = Field(..., description="Unique identifier associated with the request")


SERVICE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]+$")


class LockfileImportRequest(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=100, description="Named service within the project")
    filename: str = Field(..., min_length=1, max_length=255, description="Original primary file filename")
    content: str = Field(..., min_length=1, description="Primary file content as UTF-8 string")
    secondary_filename: str | None = Field(default=None, max_length=255, description="Optional paired secondary filename (e.g. go.sum)")
    secondary_content: str | None = Field(default=None, description="Optional paired secondary file content")
    import_method: str | None = Field(default=None, max_length=50, description="Optional explicit import method ID")
    metadata: dict[str, Any] | None = Field(default=None, description="Optional method-specific metadata")

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Service name cannot be empty or whitespace only.")
        if not SERVICE_NAME_REGEX.match(cleaned):
            raise ValueError(
                "Service name may only contain letters, numbers, underscores, hyphens, and periods."
            )
        return cleaned

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Filename cannot be empty or whitespace only.")
        return cleaned


# Modern alias
DependencyImportRequest = LockfileImportRequest


class ImportSummaryResponse(BaseModel):
    project_id: str = Field(..., description="Identifier of associated project")
    service_name: str = Field(..., description="Identifier or name of associated service")
    filename: str = Field(..., description="Original lockfile filename")
    sha256_hash: str = Field(..., description="SHA-256 digest of uploaded lockfile content")
    packages_parsed: int = Field(..., description="Total packages parsed from lockfile")
    packages_created: int = Field(..., description="New PackageVersion nodes created in database")
    packages_reused: int = Field(..., description="Existing PackageVersion nodes reused from database")
    edges_created: int = Field(..., description="New DEPENDS_ON edges created in database")
    edges_reused: int = Field(..., description="Existing DEPENDS_ON edges already present in database")
    skipped_entries: int = Field(..., description="Entries skipped due to missing version or unsupported structure")
    warnings: list[str] = Field(default_factory=list, description="Actionable non-fatal warnings")
    errors: list[str] = Field(default_factory=list, description="Actionable errors encountered during import")
    status: Literal["completed", "partially_completed", "failed"] = Field(..., description="Overall import status")
    imported_at: int = Field(..., description="Unix timestamp of the import event")
    fidelity: str = Field(default="exact_lockfile", description="Resolution fidelity classification")
    ecosystem: str = Field(default="npm", description="Package ecosystem")
    import_method: str = Field(default="lockfile", description="Import method used")
    secondary_filename: str | None = Field(default=None, description="Optional secondary filename")
    job_id: str | None = Field(default=None, description="Associated IngestionJob identifier")


class OsvImportSummaryResponse(BaseModel):
    project_id: str = Field(..., description="Project ID")
    total_package_versions: int = Field(..., description="Total package-version records considered")
    eligible_package_versions: int = Field(..., description="Eligible package versions for OSV query")
    unique_lookups: int = Field(..., description="Unique (ecosystem, package, version) lookups required")
    cache_hits: int = Field(..., description="Lookups resolved from cache without outbound network call")
    advisories_found: int = Field(..., description="Total advisory matches found")
    advisories_created: int = Field(..., description="New Vulnerability nodes created in FalkorDB")
    advisories_updated: int = Field(..., description="Existing Vulnerability nodes refreshed in FalkorDB")
    relationships_created: int = Field(..., description="New package-to-advisory relationships created")
    relationships_reused: int = Field(..., description="Existing package-to-advisory relationships reused")
    packages_with_no_advisories: int = Field(..., description="Eligible packages with zero matching advisories")
    skipped_packages: int = Field(..., description="Packages skipped due to missing version or ecosystem")
    failed_lookups: int = Field(..., description="Lookups that failed due to network or upstream errors")
    status: Literal["completed", "partial_failure", "failed", "skipped"] = Field(..., description="Overall ingestion status")
    errors: list[str] = Field(default_factory=list, description="Descriptions of any failures or issues")
    duration_ms: float = Field(..., description="Total duration of the ingestion operation in milliseconds")
    job_id: str | None = Field(default=None, description="Associated IngestionJob identifier")


class ProjectAdvisoryResponse(BaseModel):
    id: str = Field(..., description="OSV Advisory identifier (e.g. GHSA-..., CVE-...)")
    summary: str = Field(..., description="Short summary of the vulnerability")
    details: str = Field(default="", description="Detailed description of the vulnerability")
    severity: str = Field(..., description="Severity classification (CRITICAL, HIGH, MODERATE, LOW, UNKNOWN)")
    cvss: str | None = Field(default=None, description="CVSS score or vector string if available")
    aliases: list[str] = Field(default_factory=list, description="Related identifiers such as CVEs")
    published: str | None = Field(default=None, description="Publication timestamp")
    modified: str | None = Field(default=None, description="Last modification timestamp")
    source_url: str = Field(default="", description="Source URL or advisory reference")
    retrieved_at: int = Field(..., description="Unix timestamp when advisory was retrieved")
    package_version_id: str = Field(..., description="ID of affected package version node")
    package_name: str = Field(..., description="Affected package name")
    package_version: str = Field(..., description="Affected package version")
    ecosystem: str = Field(..., description="Package ecosystem (e.g. npm, PyPI)")


class VersionMatchResultResponse(BaseModel):
    package_name: str
    package_version: str
    ecosystem: str
    advisory_id: str
    status: Literal["affected", "not_affected", "unknown"]
    reason_code: str
    reason: str
    matched_range: str | None = None
    fixed_version: str | None = None
    comparator: str
    evaluated_at: int
    fingerprint: str


class VersionEvaluationRequest(BaseModel):
    package_name: str = Field(..., min_length=1, max_length=255)
    package_version: str = Field(..., min_length=1, max_length=100)
    ecosystem: str = Field(..., min_length=1, max_length=50)
    advisory: dict = Field(..., description="OSV advisory record dictionary")


class ProjectMatchResponse(BaseModel):
    project_id: str
    total_evaluated: int
    affected_count: int
    not_affected_count: int
    unknown_count: int
    relationships_persisted: int
    relationships_removed: int
    duration_ms: float
    status: Literal["completed", "partial_failure", "failed"]
    results: list[VersionMatchResultResponse] = Field(default_factory=list)
    job_id: str | None = Field(default=None, description="Associated IngestionJob identifier")


class VulnerabilityFindingResponse(BaseModel):
    id: str = Field(..., description="OSV vulnerability identifier")
    summary: str
    details: str = ""
    severity: str
    cvss: str | None = None
    aliases: list[str] = Field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    source_url: str = ""
    package_version_id: str
    package_name: str
    package_version: str
    ecosystem: str
    match_status: str
    match_reason: str
    reason_code: str
    matched_range: str | None = None
    fixed_version: str | None = None
    evaluated_at: int
    comparator: str
    fingerprint: str


class PackageVersionResponse(BaseModel):
    id: str
    name: str
    version: str
    ecosystem: str
    purl: str


# =====================================================================
# US-105: Ingestion Jobs & History Schemas
# =====================================================================

JobStatusLiteral = Literal["queued", "running", "succeeded", "partial", "failed"]
JobTypeLiteral = Literal["dependency_import", "osv_sync", "version_matching"]


class IngestionJobResponse(BaseModel):
    id: str = Field(..., description="Unique ingestion job identifier")
    project_id: str = Field(..., description="Project workspace identifier")
    job_type: JobTypeLiteral = Field(..., description="Category of ingestion job")
    status: JobStatusLiteral = Field(..., description="Lifecycle status")
    stage: str = Field(default="Queued", description="Human-readable execution stage or message")
    service_id: str | None = Field(default=None, description="Target service ID if scoped")
    service_name: str | None = Field(default=None, description="Target service name if scoped")
    processed_items: int = Field(default=0, description="Items processed so far")
    total_items: int | None = Field(default=None, description="Total expected items (null if indeterminate)")
    percentage: float | None = Field(default=None, description="Progress percentage 0-100 (null if indeterminate)")
    discovered_items: int = Field(default=0, description="Items discovered during inspection")
    created_items: int = Field(default=0, description="New entities created in graph")
    updated_items: int = Field(default=0, description="Existing entities updated in graph")
    reused_items: int = Field(default=0, description="Existing entities reused without mutation")
    skipped_items: int = Field(default=0, description="Items skipped or ignored")
    failed_items: int = Field(default=0, description="Items that failed processing")
    error_summary: str | None = Field(default=None, description="Safe, actionable error summary")
    errors: list[str] = Field(default_factory=list, description="Actionable failure items")
    warnings: list[str] = Field(default_factory=list, description="Actionable warnings")
    retry_eligible: bool = Field(default=False, description="Whether this job may be retried")
    retry_of_job_id: str | None = Field(default=None, description="Previous job ID if this is a retry")
    created_at: int = Field(..., description="UTC Unix timestamp of creation")
    started_at: int | None = Field(default=None, description="UTC Unix timestamp when execution began")
    completed_at: int | None = Field(default=None, description="UTC Unix timestamp when execution terminated")
    duration_ms: float | None = Field(default=None, description="Total execution duration in milliseconds")
    initiated_by: str | None = Field(default=None, description="Operator user identifier or email")
    filename: str | None = Field(default=None, description="Primary imported filename")
    secondary_filename: str | None = Field(default=None, description="Secondary paired filename")
    sha256_hash: str | None = Field(default=None, description="SHA-256 integrity digest")
    ecosystem: str | None = Field(default=None, description="Ecosystem identifier")
    import_method: str | None = Field(default=None, description="Import method used")
    fidelity: str | None = Field(default=None, description="Resolution fidelity classification")


class IngestionJobSummaryStats(BaseModel):
    total_runs: int = Field(default=0, description="Total number of jobs in project scope")
    running_runs: int = Field(default=0, description="Currently active running or queued jobs")
    succeeded_runs: int = Field(default=0, description="Completed jobs with succeeded status")
    failed_runs: int = Field(default=0, description="Jobs that terminated with failed status")
    partial_runs: int = Field(default=0, description="Jobs that completed with partial status")


class IngestionJobListResponse(BaseModel):
    items: list[IngestionJobResponse] = Field(default_factory=list, description="Paginated job records")
    total: int = Field(..., description="Total matching job records")
    page: int = Field(..., description="Current page number (1-indexed)")
    page_size: int = Field(..., description="Items per page")
    total_pages: int = Field(..., description="Total pages available")
    summary_stats: IngestionJobSummaryStats = Field(..., description="Project-wide run summary statistics")


class JobRetryResponse(BaseModel):
    message: str = Field(..., description="Confirmation message")
    original_job_id: str = Field(..., description="Identifier of the original job")
    new_job: IngestionJobResponse = Field(..., description="The newly queued retry job record")

