"""Normalized data structures for dependency lockfile parsers."""

from dataclasses import dataclass, field


class LockfileParseError(Exception):
    """Raised when a lockfile cannot be parsed or contains invalid syntax."""
    pass


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
