"""Shared domain models for PackageVersion, Vulnerabilities, and graph relationships."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PackageVersion:
    """Represents a unique package version node in the graph."""
    id: str
    name: str
    version: str
    ecosystem: str
    purl: str = ""
    checksum: str | None = None
    source_url: str | None = None
    environment_markers: str | None = None


@dataclass
class VulnerabilityRecord:
    """Represents an ingested security advisory / vulnerability record."""
    id: str
    summary: str
    details: str = ""
    severity: str = "UNKNOWN"
    cvss: str | None = None
    aliases: list[str] = field(default_factory=list)
    affected_ranges: str = "[]"  # JSON-serialized range objects
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source_url: str = ""
    published: str | None = None
    modified: str | None = None
    retrieved_at: int = 0
    source: str = "OSV"


@dataclass(frozen=True)
class AdvisoryLinkRecord:
    """Represents a relationship between a package version and an advisory."""
    package_version_id: str
    advisory_id: str
    created_at: int


class JobStatus:
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class JobType:
    DEPENDENCY_IMPORT = "dependency_import"
    OSV_SYNC = "osv_sync"
    VERSION_MATCHING = "version_matching"


@dataclass
class IngestionJobRecord:
    """Represents a durable ingestion job tracking progress, provenance, and outcome."""
    id: str
    project_id: str
    job_type: str
    status: str
    stage: str = "Queued"
    service_id: str | None = None
    service_name: str | None = None
    processed_items: int = 0
    total_items: int | None = None
    percentage: float | None = None
    discovered_items: int = 0
    created_items: int = 0
    updated_items: int = 0
    reused_items: int = 0
    skipped_items: int = 0
    failed_items: int = 0
    error_summary: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    retry_eligible: bool = False
    retry_of_job_id: str | None = None
    created_at: int = 0
    started_at: int | None = None
    completed_at: int | None = None
    duration_ms: float | None = None
    initiated_by: str | None = None
    filename: str | None = None
    secondary_filename: str | None = None
    sha256_hash: str | None = None
    ecosystem: str | None = None
    import_method: str | None = None
    fidelity: str | None = None
    metadata_json: str | None = None

