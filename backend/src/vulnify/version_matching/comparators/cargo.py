"""Cargo (Rust) version comparator adhering to Semantic Versioning 2.0.0."""

import semver
from vulnify.version_matching.comparators.base import BaseVersionComparator, InvalidVersionError


class CargoVersionComparator(BaseVersionComparator):
    """Comparator for Cargo / crates.io versions adhering to Semantic Versioning 2.0.0."""

    @property
    def name(self) -> str:
        return "cargo-semver-2.0.0"

    @property
    def ecosystem(self) -> str:
        return "crates.io"

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
                f"Invalid Cargo SemVer string '{version_str}' (normalized: '{normalized}') for ecosystem crates.io: {exc}"
            ) from exc
