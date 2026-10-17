"""Dependency parsers and capability registry for supported package ecosystems."""

from vulnify.parsers.cargo import CargoLockfileParser, parse_cargo_lock
from vulnify.parsers.golang import GoModParser, parse_go_mod, parse_go_sum
from vulnify.parsers.models import (
    BaseDependencyParser,
    DependencyParseError,
    FidelityLevel,
    LockfileParseError,
    ParsedDependencyEdge,
    ParsedGraph,
    ParsedPackageVersion,
)
from vulnify.parsers.npm import NpmLockfileParser, parse_npm_lockfile
from vulnify.parsers.python import (
    PythonDependencyParser,
    parse_poetry_lock,
    parse_pylock_toml,
    parse_requirements_txt,
    parse_uv_lock,
)
from vulnify.parsers.registry import (
    EcosystemCapabilitiesResponse,
    EcosystemCapability,
    EcosystemRegistry,
    ImportFieldDefinition,
    ImportMethodCapability,
    get_ecosystem_registry,
    get_supported_ecosystem_ids,
)

__all__ = [
    "BaseDependencyParser",
    "CargoLockfileParser",
    "DependencyParseError",
    "EcosystemCapabilitiesResponse",
    "EcosystemCapability",
    "EcosystemRegistry",
    "FidelityLevel",
    "GoModParser",
    "ImportFieldDefinition",
    "ImportMethodCapability",
    "LockfileParseError",
    "NpmLockfileParser",
    "ParsedDependencyEdge",
    "ParsedGraph",
    "ParsedPackageVersion",
    "PythonDependencyParser",
    "get_ecosystem_registry",
    "get_supported_ecosystem_ids",
    "parse_cargo_lock",
    "parse_go_mod",
    "parse_go_sum",
    "parse_npm_lockfile",
    "parse_poetry_lock",
    "parse_pylock_toml",
    "parse_requirements_txt",
    "parse_uv_lock",
]
