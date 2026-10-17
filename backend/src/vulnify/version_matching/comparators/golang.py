"""Go module version comparator adhering to Semantic Versioning with v-prefix stripping."""

import semver
from vulnify.version_matching.comparators.base import BaseVersionComparator, InvalidVersionError


class GoVersionComparator(BaseVersionComparator):
    """Comparator for Go module versions adhering to Semantic Versioning."""

    @property
    def name(self) -> str:
        return "go-semver-v"

    @property
    def ecosystem(self) -> str:
        return "Go"

    def normalize(self, version_str: str) -> str:
        cleaned = self.strip_prefix(version_str)
        if cleaned == "0":
            return "0.0.0-0"
        return cleaned

    def parse(self, version_str: str) -> semver.Version:
        normalized = self.normalize(version_str)
        try:
            return semver.Version.parse(normalized)
        except ValueError as exc:
            raise InvalidVersionError(
                f"Invalid Go version string '{version_str}' (normalized: '{normalized}') for ecosystem Go: {exc}"
            ) from exc
