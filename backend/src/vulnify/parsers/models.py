"""Normalized data structures for dependency lockfile and manifest parsers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FidelityLevel(str, Enum):
    """Classification of dependency resolution fidelity."""
    EXACT_LOCKFILE = "exact_lockfile"
    CHECKSUM_VERIFIED = "checksum_verified"
    TRANSITIVE_RESOLVED = "transitive_resolved"
    MANIFEST_DECLARED = "manifest_declared"
    PARTIAL_RESOLUTION = "partial_resolution"


class DependencyParseError(Exception):
    """Raised when a dependency file cannot be parsed or contains invalid syntax."""
    pass


# Backward compatibility alias
LockfileParseError = DependencyParseError


from vulnify.models import PackageVersion

# Backward compatibility alias
ParsedPackageVersion = PackageVersion


@dataclass(frozen=True)
class ParsedDependencyEdge:
    source_id: str
    target_id: str
    direct: bool = False


@dataclass
class ParsedGraph:
    packages: list[ParsedPackageVersion] = field(default_factory=list)
    edges: list[ParsedDependencyEdge] = field(default_factory=list)
    direct_dependency_ids: list[str] = field(default_factory=list)
    skipped_entries: int = 0
    warnings: list[str] = field(default_factory=list)
    parser_id: str = "unknown"
    format_version: str = "unknown"
    fidelity: str = "exact_lockfile"


class BaseDependencyParser(ABC):
    """Common parser interface for ecosystem dependency inputs."""

    @property
    @abstractmethod
    def parser_id(self) -> str:
        """Stable internal identifier of this parser."""
        pass

    @property
    @abstractmethod
    def ecosystem(self) -> str:
        """Primary package ecosystem handled by this parser."""
        pass

    @property
    @abstractmethod
    def supported_filenames(self) -> list[str]:
        """Accepted filenames for this parser."""
        pass

    @abstractmethod
    def parse(
        self,
        content: str | bytes,
        filename: str,
        secondary_content: str | bytes | None = None,
        secondary_filename: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ParsedGraph:
        """Parse dependency input content deterministically without code execution."""
        pass

