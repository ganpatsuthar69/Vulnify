"""Pydantic v2 data models for Vulnify user management, authentication, and health."""

import re
from typing import Any, Literal
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
# US-201: Findings List Schemas
# =====================================================================

class ProjectServiceResponse(BaseModel):
    id: str = Field(..., description="Unique service identifier")
    name: str = Field(..., description="Service display name")


FindingPathStatusLiteral = Literal["path_found", "no_path_found", "unavailable"]


class FindingItemResponse(BaseModel):
    id: str = Field(..., description="Deterministic, unique finding identifier")
    project_id: str = Field(..., description="Associated project identifier")
    service_id: str = Field(..., description="Associated service identifier")
    service_name: str = Field(..., description="Associated service name")
    advisory_id: str = Field(..., description="OSV or CVE advisory identifier")
    advisory_summary: str = Field(default="", description="Advisory summary")
    source_url: str = Field(default="", description="Upstream advisory URL")
    package_name: str = Field(..., description="Name of affected package")
    ecosystem: str = Field(..., description="Package ecosystem (npm, PyPI, Cargo, Go)")
    package_version: str = Field(..., description="Installed/matched package version")
    package_version_id: str = Field(..., description="PURL or graph identifier of package version")
    priority: str = Field(default="unknown", description="Vulnify priority band (unknown, Low, Medium, High, Highest)")
    priority_reasons: list[str] = Field(default_factory=list, description="Transparent, deterministic reasons explaining priority band")
    scoring_version: str = Field(default="v1.0.0", description="Scoring engine rule version applied")
    status: str = Field(default="open", description="Triage status (open, under_investigation, affected, not_affected, fixed)")
    path_depth: int | None = Field(default=None, description="Shortest dependency path depth from service (1 for direct, >=2 for transitive)")
    path_status: FindingPathStatusLiteral = Field(default="path_found", description="Status of dependency path evidence")
    match_reason: str = Field(default="", description="Ecosystem-aware version match explanation")
    reason_code: str = Field(default="", description="Machine-readable match reason code")
    matched_range: str | None = Field(default=None, description="Matched advisory version constraint range")
    fixed_version: str | None = Field(default=None, description="Earliest fixed version")
    severity: str = Field(default="UNKNOWN", description="Advisory severity from OSV")
    retrieved_at: int | None = Field(default=None, description="Advisory retrieval timestamp")


class FindingListResponse(BaseModel):
    items: list[FindingItemResponse] = Field(default_factory=list, description="Paginated finding items")
    page: int = Field(..., description="Current page (1-indexed)")
    page_size: int = Field(..., description="Requested page size")
    total: int = Field(..., description="Total matching findings for active filters")
    total_pages: int = Field(..., description="Total available pages")


class FindingSummaryResponse(BaseModel):
    project_id: str = Field(..., description="Project workspace identifier")
    advisory_matches: int = Field(..., ge=0, description="Total matching advisory findings")
    findings_with_path: int = Field(..., ge=0, description="Findings with confirmed dependency path")
    findings_without_path: int = Field(..., ge=0, description="Findings without confirmed dependency path")
    findings_needing_decision: int = Field(..., ge=0, description="Findings requiring a triage decision")


# =====================================================================
# US-207: Honest Empty and Warning States Schemas
# =====================================================================

DataQualityCategoryLiteral = Literal[
    "no_path",
    "missing_topology",
    "stale_advisory_data",
    "partial_import",
]
DataQualitySeverityLiteral = Literal["warning", "info", "error"]


class DataQualityWarning(BaseModel):
    code: str = Field(..., description="Machine-readable warning code (e.g. MISSING_TOPOLOGY, STALE_ADVISORY_DATA, UNKNOWN_ADVISORY_FRESHNESS, PARTIAL_IMPORT_DETECTED, NO_PATH_DISCLAIMER)")
    category: DataQualityCategoryLiteral = Field(..., description="Warning category")
    severity: DataQualitySeverityLiteral = Field(default="warning", description="Severity classification")
    title: str = Field(..., description="Short, human-readable warning summary")
    message: str = Field(..., description="Actionable explanation emphasizing data bounds and safety implications")
    resource_id: str | None = Field(default=None, description="Associated resource identifier (service, job, or advisory ID)")
    details: dict[str, Any] = Field(default_factory=dict, description="Structured evaluation details (e.g. age_days, threshold_days, failed_items)")


class ProjectDataQualityResponse(BaseModel):
    project_id: str = Field(..., description="Project workspace identifier")
    has_warnings: bool = Field(..., description="True if any data quality warnings are present")
    warning_count: int = Field(..., description="Total count of active data quality warnings")
    warnings: list[DataQualityWarning] = Field(default_factory=list, description="Active data quality warnings")
    evaluated_at: int = Field(..., description="Unix timestamp of evaluation")


class FindingDetailResponse(FindingItemResponse):
    advisory_details: str = Field(default="", description="Full advisory text and description from OSV")
    aliases: list[str] = Field(default_factory=list, description="Related identifiers such as CVEs or GHSAs")
    warnings: list[DataQualityWarning] = Field(default_factory=list, description="Contextual data quality warnings for this finding and project")


# =====================================================================
# US-204: Dependency Path Visualization Schemas
# =====================================================================

class NodeProvenance(BaseModel):
    source_filename: str | None = Field(default=None, description="Imported lockfile or manifest filename")
    content_hash: str | None = Field(default=None, description="SHA-256 digest of import source")
    imported_at: int | None = Field(default=None, description="Timestamp of dependency graph ingestion")
    classification: str = Field(default="manifest", description="Provenance classification (manifest, lockfile, synthetic)")
    origin: str = Field(default="stored_graph", description="Data origin guarantee")


class PathNode(BaseModel):
    id: str = Field(..., description="Unique node identifier in graph")
    node_type: Literal["service", "package"] = Field(..., description="Entity classification")
    display_name: str = Field(..., description="Human-readable label for graph node")
    package_name: str | None = Field(default=None, description="Package name if package node")
    package_version: str | None = Field(default=None, description="Package version if package node")
    ecosystem: str | None = Field(default=None, description="Ecosystem if package node")
    purl: str | None = Field(default=None, description="Package URL if package node")
    is_target: bool = Field(default=False, description="Whether this node is the affected package version")
    is_entry_point: bool = Field(default=False, description="Whether this node is the service entry point")
    provenance: NodeProvenance = Field(default_factory=NodeProvenance, description="Provenance audit details")


class PathEdge(BaseModel):
    id: str = Field(..., description="Unique edge identifier")
    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    relationship_type: str = Field(default="DEPENDS_ON", description="Graph relationship type")
    direct: bool = Field(default=False, description="True if direct dependency from service, false if transitive")
    origin: str = Field(default="manifest", description="Relationship provenance origin")


class DependencyPath(BaseModel):
    id: str = Field(..., description="Deterministic, unique path identifier")
    depth: int = Field(..., description="Path depth (hop count / edge count)")
    is_direct: bool = Field(..., description="True if depth == 1 (direct dependency)")
    nodes: list[PathNode] = Field(default_factory=list, description="Ordered nodes from service to affected package")
    edges: list[PathEdge] = Field(default_factory=list, description="Ordered dependency edges along the path")
    summary_text: str = Field(default="", description="Semantic screen-reader accessible path summary")


class FindingPathsResponse(BaseModel):
    project_id: str = Field(..., description="Associated project identifier")
    finding_id: str = Field(..., description="Finding identifier")
    service_id: str = Field(..., description="Root service identifier")
    service_name: str = Field(..., description="Root service name")
    advisory_id: str = Field(..., description="Target OSV / CVE advisory identifier")
    package_name: str = Field(..., description="Target affected package name")
    package_version: str = Field(..., description="Target affected package version")
    package_version_id: str = Field(..., description="Target affected package version node ID")
    paths: list[DependencyPath] = Field(default_factory=list, description="Ordered shortest dependency paths")
    total_paths_found: int = Field(..., description="Total paths found within search bounds")
    max_depth_applied: int = Field(..., description="Traversal depth limit applied")
    limit_applied: int = Field(..., description="Path count limit applied")
    is_truncated: bool = Field(default=False, description="True if more paths exist beyond limit_applied")
    has_path: bool = Field(..., description="True if at least one dependency path exists")
    evaluated_at: int = Field(..., description="Evaluation timestamp")
    no_path_message: str | None = Field(default=None, description="Explicit disclaimer explaining search bounds and that absence of path does not guarantee safety")
    warnings: list[DataQualityWarning] = Field(default_factory=list, description="Contextual data quality warnings")



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


# =====================================================================
# US-401 / US-501: Upgrade Candidates Schemas
# =====================================================================

CandidateClassificationLiteral = Literal["recommended", "major", "patch", "minor", "unknown"]
CandidateFixStatusLiteral = Literal["fix_supported", "not_fixed", "unknown"]
CompatibilityStatusLiteral = Literal["compatible", "conflict", "unknown"]
BreakingChangeRiskLiteral = Literal["high", "low", "unknown"]


class UpgradeCandidateItem(BaseModel):
    target_version: str = Field(..., description="Suggested candidate package version")
    classification: CandidateClassificationLiteral = Field(..., description="Primary candidate classification ('recommended', 'major', 'patch', 'minor')")
    label: str = Field(..., description="Human-readable badge label ('Recommended', 'Major version', 'Patch only', 'Minor version')")
    labels: list[str] = Field(default_factory=list, description="All applicable candidate labels including 'recommended', 'major version', 'patch only'")
    semver_diff: str = Field(..., description="SemVer delta classification ('major', 'minor', 'patch', 'unknown')")
    is_recommended: bool = Field(default=False, description="True if this candidate is the primary recommended remediation target")
    fix_status: CandidateFixStatusLiteral = Field(default="fix_supported", description="Security-fix support evidence state")
    compatibility_status: CompatibilityStatusLiteral = Field(default="unknown", description="Compatibility evaluation state (compatible, conflict, unknown)")
    breaking_change_risk: BreakingChangeRiskLiteral = Field(default="unknown", description="Assessed risk of breaking API changes")
    caveats: list[str] = Field(default_factory=list, description="Contextual compatibility caveats and dependency notes")
    evidence_source: str = Field(default="Advisory fixed version declaration", description="Origin of candidate remediation recommendation")


class UpgradeCandidatesResponse(BaseModel):
    project_id: str = Field(..., description="Associated project identifier")
    finding_id: str = Field(..., description="Target finding identifier")
    advisory_id: str = Field(..., description="Target advisory identifier")
    package_name: str = Field(..., description="Target package name")
    current_version: str = Field(..., description="Currently installed / matched package version")
    ecosystem: str = Field(..., description="Package ecosystem (npm, PyPI, Cargo, Go)")
    service_id: str = Field(..., description="Associated service identifier")
    service_name: str = Field(..., description="Associated service name")
    path_depth: int | None = Field(default=None, description="Shortest dependency path depth from root service")
    is_transitive: bool = Field(default=False, description="True if dependency is transitive (path depth > 1)")
    has_fix: bool = Field(..., description="Whether a verified fixed version is available from upstream advisory")
    candidates: list[UpgradeCandidateItem] = Field(default_factory=list, description="Ranked upgrade candidate targets")
    no_fix_message: str | None = Field(default=None, description="Explicit disclaimer when no upstream fix exists")
    remediation_guidance: str | None = Field(default=None, description="Defensive guidance for mitigation and testing")
    safety_disclaimer: str = Field(
        default="No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.",
        description="Mandatory disclaimer: absence of detected conflict does not guarantee runtime safety",
    )
    evaluated_at: int = Field(..., description="Unix timestamp of candidate evaluation")


class ProjectUpgradeCandidatesResponse(BaseModel):
    project_id: str = Field(..., description="Project workspace identifier")
    total_findings: int = Field(..., description="Total confirmed findings evaluated")
    findings_with_fix: int = Field(..., description="Findings with at least one verified upgrade target")
    findings_without_fix: int = Field(..., description="Findings with no upstream fix published")
    items: list[UpgradeCandidatesResponse] = Field(default_factory=list, description="Per-finding upgrade candidate evaluations")
    safety_disclaimer: str = Field(
        default="No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.",
        description="Mandatory disclaimer: absence of detected conflict does not guarantee runtime safety",
    )
    evaluated_at: int = Field(..., description="Unix timestamp of project evaluation")


# =====================================================================
# US-501 / US-502: Fix Simulation Schemas
# =====================================================================

SimulationMethodLiteral = Literal["simulated_from_metadata", "verified_in_sandbox"]
SimulationCheckStatusLiteral = Literal["passed", "failed", "unknown", "not_evaluated"]
SimulationFindingStatusLiteral = Literal["expected_resolved", "still_affected", "newly_introduced", "unknown"]


class SimulationCheckItem(BaseModel):
    name: str = Field(..., description="Name of verification check")
    status: SimulationCheckStatusLiteral = Field(..., description="Outcome of the check")
    description: str = Field(..., description="Detailed explanation of the check and boundary")


class SimulatedFindingDelta(BaseModel):
    finding_id: str = Field(..., description="Finding identifier or newly discovered vulnerability key")
    advisory_id: str = Field(..., description="Target OSV / CVE advisory ID")
    package_name: str = Field(..., description="Target package name")
    installed_version: str = Field(..., description="Baseline version")
    target_version: str = Field(..., description="Simulated target version")
    severity: str = Field(default="UNKNOWN", description="Advisory severity")
    status: SimulationFindingStatusLiteral = Field(..., description="Outcome delta: expected_resolved, still_affected, newly_introduced, or unknown")
    explanation: str = Field(..., description="Transparent justification based on affected ranges and fixed versions")
    source_url: str | None = Field(default=None, description="Upstream advisory source reference")


class SimulationRequest(BaseModel):
    finding_id: str | None = Field(default=None, description="Optional finding ID to pre-populate package metadata")
    package_name: str = Field(..., min_length=1, description="Canonical package name to simulate upgrading")
    current_version: str = Field(..., min_length=1, description="Currently installed package version in baseline")
    target_version: str = Field(..., min_length=1, description="Proposed upgrade target version")
    ecosystem: str = Field(default="npm", description="Package ecosystem (npm, PyPI, Cargo, Go)")
    service_id: str | None = Field(default=None, description="Optional service scope identifier")


class SimulationResponse(BaseModel):
    id: str = Field(..., description="Deterministic simulation run identifier")
    project_id: str = Field(..., description="Target project identifier")
    package_name: str = Field(..., description="Target package name")
    current_version: str = Field(..., description="Currently installed baseline version")
    target_version: str = Field(..., description="Proposed upgrade target version")
    ecosystem: str = Field(..., description="Package ecosystem")
    service_id: str | None = Field(default=None, description="Target service ID if scoped")
    service_name: str | None = Field(default=None, description="Target service display name if scoped")
    method: SimulationMethodLiteral = Field(default="simulated_from_metadata", description="AC-2: Simulation methodology label")
    method_description: str = Field(default="Evaluated on an in-memory graph overlay using OSV advisory version metadata and lockfile dependency paths without mutating stored graph data.")
    is_simulation: bool = Field(default=True, description="Always true; flags this result as a dry-run simulation")
    real_graph_mutated: bool = Field(default=False, description="AC-3: Explicit guarantee that the real graph was NOT mutated")
    baseline_id: str = Field(..., description="Digest or timestamp identifying the baseline graph snapshot")
    is_transitive: bool = Field(default=False, description="True if target package is a transitive dependency in the service")
    path_depth: int | None = Field(default=None, description="Shortest path depth in baseline graph")
    paths_severed_count: int = Field(default=0, description="Number of vulnerable reachability paths broken by the proposed change")
    paths_remaining_count: int = Field(default=0, description="Residual dependency paths still reaching vulnerable versions")
    dependent_services: list[str] = Field(default_factory=list, description="Services in project that depend on this package")
    cleared_findings: list[SimulatedFindingDelta] = Field(default_factory=list, description="AC-1: Findings expected to be cleared/resolved by target version")
    unchanged_findings: list[SimulatedFindingDelta] = Field(default_factory=list, description="AC-1: Findings remaining active or unaffected")
    newly_introduced_findings: list[SimulatedFindingDelta] = Field(default_factory=list, description="AC-1: New vulnerabilities reported on target version")
    total_findings_cleared: int = Field(default=0, description="Total count of findings expected to be resolved")
    total_findings_unchanged: int = Field(default=0, description="Total count of unchanged / residual findings")
    total_findings_introduced: int = Field(default=0, description="Total count of newly introduced vulnerabilities")
    compatibility_status: CompatibilityStatusLiteral = Field(default="compatible", description="Compatibility assessment state")
    breaking_change_risk: BreakingChangeRiskLiteral = Field(default="low", description="SemVer breaking change risk assessment")
    resolver_status: str = Field(default="not_evaluated", description="Real package-manager resolver status (honest boundary: graph analysis only)")
    compatibility_caveats: list[str] = Field(default_factory=list, description="Explicit caveats and warnings regarding constraints and dependencies")
    checks_performed: list[SimulationCheckItem] = Field(default_factory=list, description="Detailed verification checklist with transparent statuses")
    safety_disclaimer: str = Field(
        default="A simulation is a prediction based on defined metadata and graph checks, not proof that a dependency upgrade will succeed at build or runtime. Upgrades must be validated through automated integration testing.",
        description="Mandatory disclaimer: simulation is not proof of safety",
    )
    created_at: int = Field(..., description="UTC Unix timestamp of simulation run")


class SimulationListResponse(BaseModel):
    items: list[SimulationResponse] = Field(default_factory=list, description="Recent simulation runs for this project")
    total: int = Field(default=0, description="Total recorded simulations")


# =====================================================================
# US-503 / US-504: GitHub Issue Remediation Schemas
# =====================================================================


class GitHubIntegrationStatusResponse(BaseModel):
    configured: bool = Field(..., description="True if GITHUB_TOKEN is configured in backend environment")
    default_owner: str | None = Field(default=None, description="Configured default repository owner")
    default_repo: str | None = Field(default=None, description="Configured default repository name")
    target_repo: str = Field(..., description="Default target repository in owner/repo format")
    api_base_url: str = Field(..., description="Configured GitHub API base URL")


class GitHubIssuePreviewRequest(BaseModel):
    target_repo: str | None = Field(default=None, description="Optional target repository override (owner/repo)")
    target_version: str | None = Field(default=None, description="Optional remediation target version from US-401/US-501")
    title_override: str | None = Field(default=None, description="Optional user-edited title")
    operator_notes: str | None = Field(default=None, description="Optional operator notes to include in issue body")


class GitHubIssuePreviewResponse(BaseModel):
    project_id: str = Field(..., description="Project identifier")
    finding_id: str = Field(..., description="Finding identifier")
    package_name: str = Field(..., description="Package name")
    current_version: str = Field(..., description="Currently installed package version")
    target_version: str | None = Field(default=None, description="Remediation target version if available")
    advisory_id: str = Field(..., description="OSV/CVE advisory identifier")
    severity: str = Field(..., description="Advisory severity rating")
    title: str = Field(..., description="Generated issue title")
    body: str = Field(..., description="Structured markdown issue body (safe plain text/markdown, never raw HTML)")
    target_repo: str = Field(..., description="Target repository (owner/repo)")
    plan_hash: str = Field(..., description="Cryptographic SHA-256 plan hash binding the preview content (US-503)")
    can_submit: bool = Field(default=True, description="True if integration is configured and preview is valid")
    configuration_warning: str | None = Field(default=None, description="Warning if GITHUB_TOKEN is not configured")


class GitHubIssueCreateRequest(BaseModel):
    plan_hash: str = Field(..., min_length=1, description="Plan hash from preview confirming user reviewed the exact plan (US-503)")
    title: str = Field(..., min_length=1, max_length=256, description="Issue title approved by user")
    body: str = Field(..., min_length=1, max_length=65536, description="Structured issue body approved by user")
    target_repo: str = Field(..., min_length=1, max_length=256, description="Target repository in owner/repo format")
    target_version: str | None = Field(default=None, description="Target package version")
    confirmed: bool = Field(..., description="Mandatory explicit user approval flag (US-504)")


class GitHubIssueRecordResponse(BaseModel):
    id: str = Field(..., description="Internal issue record identifier")
    project_id: str = Field(..., description="Project identifier")
    finding_id: str = Field(..., description="Finding identifier")
    package_name: str = Field(..., description="Package name")
    target_version: str | None = Field(default=None, description="Target version")
    issue_number: int = Field(..., description="GitHub issue number returned by GitHub API")
    issue_url: str = Field(..., description="Official GitHub issue URL returned by GitHub API")
    title: str = Field(..., description="Issue title")
    target_repo: str = Field(..., description="Repository owner/repo")
    state: str = Field(default="open", description="Issue state (open, closed)")
    plan_hash: str = Field(..., description="Plan hash bound to this issue creation")
    created_at: int = Field(..., description="UTC timestamp of issue creation")
    created_by: str = Field(..., description="User email or identity who approved the issue")
    is_duplicate: bool = Field(default=False, description="True if this request returned an existing issue (idempotent duplicate prevention)")
    message: str = Field(..., description="Action summary message")


class GitHubIssueListResponse(BaseModel):
    items: list[GitHubIssueRecordResponse] = Field(default_factory=list, description="List of created remediation issues")
    total: int = Field(default=0, description="Total issues created for project")

