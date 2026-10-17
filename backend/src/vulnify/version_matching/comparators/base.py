import re
from abc import ABC, abstractmethod
from typing import Any


class InvalidVersionError(ValueError):
    """Raised when a version string cannot be parsed according to ecosystem rules."""
    pass


class UnsupportedEcosystemError(ValueError):
    """Raised when an ecosystem has no implemented comparator."""
    pass


class BaseVersionComparator(ABC):
    """Abstract base class defining version parsing, normalization, and comparison semantics."""

    @staticmethod
    def strip_prefix(version_str: str) -> str:
        """Strip leading prefixes ('v', 'V', '=') and validate non-empty string."""
        if not version_str or not isinstance(version_str, str):
            raise InvalidVersionError("Version string cannot be empty or non-string.")

        cleaned = version_str.strip()
        cleaned = re.sub(r"^[vV=]+", "", cleaned).strip()

        if not cleaned:
            raise InvalidVersionError("Version string cannot be empty after prefix stripping.")

        return cleaned

    @property
    @abstractmethod
    def name(self) -> str:
        """The identifier of this comparator (e.g. 'npm-semver-2.0.0', 'pypi-pep440')."""
        pass

    @property
    @abstractmethod
    def ecosystem(self) -> str:
        """The canonical ecosystem name (e.g. 'npm', 'PyPI')."""
        pass

    @abstractmethod
    def normalize(self, version_str: str) -> str:
        """Sanitize and normalize a version string according to ecosystem rules."""
        pass

    @abstractmethod
    def parse(self, version_str: str) -> Any:
        """Parse version string into an internal comparable object or raise InvalidVersionError."""
        pass

    def is_valid(self, version_str: str) -> bool:
        """Check whether a version string is valid under this ecosystem's grammar."""
        try:
            self.parse(version_str)
            return True
        except (InvalidVersionError, Exception):
            return False

    def compare(self, v1_str: str, v2_str: str) -> int:
        """Compare two version strings: returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2."""
        parsed1 = self.parse(v1_str)
        parsed2 = self.parse(v2_str)
        if parsed1 < parsed2:
            return -1
        if parsed1 > parsed2:
            return 1
        return 0
