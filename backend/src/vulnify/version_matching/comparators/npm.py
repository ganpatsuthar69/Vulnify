"""Npm and SemVer 2.0.0 version comparator implementation."""

import re
import semver
from vulnify.version_matching.comparators.base import BaseVersionComparator, InvalidVersionError


class NpmVersionComparator(BaseVersionComparator):
    """Comparator for npm package versions adhering to Semantic Versioning 2.0.0."""

    @property
    def name(self) -> str:
        return "npm-semver-2.0.0"

    @property
    def ecosystem(self) -> str:
        return "npm"

    def normalize(self, version_str: str) -> str:
        """Strip prefixes ('v', '=') and normalize loose numeric representations."""
        cleaned = self.strip_prefix(version_str)

        # Special OSV marker '0' represents open-ended earliest bound
        if cleaned == "0":
            return "0.0.0-0"

        # Separate pre-release / build metadata from core version
        # e.g. "1.2-alpha.1" or "1.2+build"
        match = re.match(r"^(\d+(?:\.\d+)*)(.*)$", cleaned)
        if match:
            core_numbers = match.group(1).split(".")
            suffix = match.group(2)
            if len(core_numbers) == 1:
                cleaned = f"{core_numbers[0]}.0.0{suffix}"
            elif len(core_numbers) == 2:
                cleaned = f"{core_numbers[0]}.{core_numbers[1]}.0{suffix}"

        return cleaned

    def parse(self, version_str: str) -> semver.Version:
        """Parse version string into a semver.Version object."""
        normalized = self.normalize(version_str)
        try:
            return semver.Version.parse(normalized)
        except ValueError as exc:
            raise InvalidVersionError(
                f"Invalid SemVer string '{version_str}' (normalized: '{normalized}') for ecosystem npm: {exc}"
            ) from exc
