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
