"""PyPI version comparator adhering to PEP 440 specification."""

import re
from packaging.version import InvalidVersion, Version
from vulnify.version_matching.comparators.base import BaseVersionComparator, InvalidVersionError


class PyPIVersionComparator(BaseVersionComparator):
    """Comparator for PyPI package versions adhering to Python's PEP 440 specification."""

    @property
    def name(self) -> str:
        return "pypi-pep440"

    @property
    def ecosystem(self) -> str:
        return "PyPI"

    def normalize(self, version_str: str) -> str:
        """Strip leading prefixes and clean whitespace."""
        return self.strip_prefix(version_str)

    def parse(self, version_str: str) -> Version:
        """Parse version string into a packaging.version.Version object."""
        normalized = self.normalize(version_str)
        try:
            return Version(normalized)
        except InvalidVersion as exc:
            raise InvalidVersionError(
                f"Invalid PEP 440 version string '{version_str}' (normalized: '{normalized}') for ecosystem PyPI: {exc}"
            ) from exc
