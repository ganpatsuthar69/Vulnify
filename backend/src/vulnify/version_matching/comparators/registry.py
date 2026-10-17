"""Comparator registry mapping package ecosystems to their respective comparison strategies."""

from vulnify.version_matching.comparators.base import (
    BaseVersionComparator,
    UnsupportedEcosystemError,
)
from vulnify.version_matching.comparators.npm import NpmVersionComparator
from vulnify.version_matching.comparators.pypi import PyPIVersionComparator

_NPM_COMPARATOR = NpmVersionComparator()
_PYPI_COMPARATOR = PyPIVersionComparator()

_ECOSYSTEM_REGISTRY: dict[str, BaseVersionComparator] = {
    "npm": _NPM_COMPARATOR,
    "javascript": _NPM_COMPARATOR,
    "node": _NPM_COMPARATOR,
    "pypi": _PYPI_COMPARATOR,
    "python": _PYPI_COMPARATOR,
}


def get_comparator(ecosystem: str) -> BaseVersionComparator:
    """Retrieve the version comparator for the specified ecosystem.
    
    Raises UnsupportedEcosystemError if the ecosystem is not supported.
    """
    if not ecosystem or not isinstance(ecosystem, str):
        raise UnsupportedEcosystemError(f"Ecosystem name must be a non-empty string, got: {ecosystem!r}")

    normalized = ecosystem.strip().lower()
    comparator = _ECOSYSTEM_REGISTRY.get(normalized)
    if comparator is None:
        supported = ", ".join(sorted({c.ecosystem for c in _ECOSYSTEM_REGISTRY.values()}))
        raise UnsupportedEcosystemError(
            f"Ecosystem '{ecosystem}' is not supported for version matching. Supported ecosystems: {supported}."
        )

    return comparator


def get_range_comparator(range_type: str, ecosystem: str) -> BaseVersionComparator:
    """Select the appropriate comparator based on the OSV range type and package ecosystem.
    
    In OSV:
    - 'SEMVER' range types strictly follow Semantic Versioning 2.0.0 rules.
    - 'ECOSYSTEM' range types follow the package's specific ecosystem rules.
    """
    rt_upper = range_type.strip().upper() if range_type else ""
    if rt_upper == "SEMVER":
        return _NPM_COMPARATOR
    if rt_upper == "ECOSYSTEM":
        return get_comparator(ecosystem)

    raise ValueError(f"Unsupported OSV range type: {range_type!r}")
