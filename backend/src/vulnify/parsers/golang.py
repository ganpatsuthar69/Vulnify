"""Deterministic parser for Go modules (go.mod and paired go.sum) without code execution."""

import re
from typing import Any

from vulnify.models import PackageVersion
from vulnify.parsers.models import (
    BaseDependencyParser,
    DependencyParseError,
    FidelityLevel,
    ParsedDependencyEdge,
    ParsedGraph,
    ParsedPackageVersion,
)


def _decode_content(content: str | bytes) -> str:
    if isinstance(content, bytes):
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DependencyParseError("Malformed file: Go dependency file must be valid UTF-8 encoded text.") from exc
    return content


def parse_go_sum(content: str | bytes) -> dict[tuple[str, str], str]:
    """Parse a go.sum checksum file into a map of (module_path, version) -> checksum."""
    content_str = _decode_content(content)
    checksums: dict[tuple[str, str], str] = {}

    for line in content_str.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue

        parts = line.split()
        if len(parts) >= 3:
            mod_path = parts[0].strip()
            ver_part = parts[1].strip()
            checksum = parts[2].strip()

            # Strip /go.mod suffix if present
            clean_ver = ver_part[:-7] if ver_part.endswith("/go.mod") else ver_part
            key = (mod_path, clean_ver)
            if key not in checksums or not ver_part.endswith("/go.mod"):
                checksums[key] = checksum

    return checksums


def parse_go_mod(
    content: str | bytes,
    filename: str = "go.mod",
    secondary_content: str | bytes | None = None,
    secondary_filename: str | None = None,
) -> ParsedGraph:
    """Parse a go.mod file, optionally matching checksums from a paired go.sum file."""
    content_str = _decode_content(content)
    if not content_str.strip():
        raise DependencyParseError("go.mod content is empty.")

    checksums: dict[tuple[str, str], str] = {}
    if secondary_content is not None and str(secondary_content).strip():
        checksums = parse_go_sum(secondary_content)

    module_name = ""
    unique_packages: dict[str, ParsedPackageVersion] = {}
    direct_dep_ids: list[str] = []
    skipped_entries = 0
    warnings: list[str] = []

    in_require_block = False

    for line_num, raw_line in enumerate(content_str.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        # Extract module declaration
        if line.startswith("module "):
            parts = line.split()
            if len(parts) >= 2:
                module_name = parts[1].strip()
            continue

        # Detect require block entry / exit
        if line == "require (" or line.startswith("require ("):
            in_require_block = True
            continue
        elif in_require_block and line == ")":
            in_require_block = False
            continue

        # Parse require statement
        req_line = ""
        if in_require_block:
            req_line = line
        elif line.startswith("require "):
            req_line = line[8:].strip()

        if req_line:
            # Check for // indirect comment
            is_indirect = "// indirect" in req_line
            # Strip comments
            comment_idx = req_line.find("//")
            clean_spec = req_line[:comment_idx].strip() if comment_idx != -1 else req_line.strip()

            parts = clean_spec.split()
            if len(parts) >= 2:
                mod_path = parts[0].strip()
                version = parts[1].strip()

                # Basic validation for module path and version
                if not mod_path or not version:
                    skipped_entries += 1
                    warnings.append(f"Line {line_num}: invalid module or version in require clause.")
                    continue

                pv_id = f"golang:{mod_path}@{version}"
                purl = f"pkg:golang/{mod_path}@{version}"
                checksum = checksums.get((mod_path, version))

                pv = PackageVersion(
                    id=pv_id,
                    name=mod_path,
                    version=version,
                    ecosystem="Go",
                    purl=purl,
                    checksum=checksum,
                )
                unique_packages[pv_id] = pv

                if not is_indirect:
                    direct_dep_ids.append(pv_id)
            else:
                skipped_entries += 1
                warnings.append(f"Line {line_num}: skipping unparseable require line '{req_line}'.")

    # If no explicit direct dependencies were marked (all indirect or none specified), treat all as candidates
    if not direct_dep_ids and unique_packages:
        direct_dep_ids = list(unique_packages.keys())

    fidelity = (
        FidelityLevel.CHECKSUM_VERIFIED.value
        if checksums
        else FidelityLevel.EXACT_LOCKFILE.value
    )

    if not checksums:
        warnings.append(
            "go.mod was imported without paired go.sum; module checksum verification was not performed."
        )

    return ParsedGraph(
        packages=list(unique_packages.values()),
        edges=[],  # go.mod declares service dependencies; inter-module edges are resolved via Go tooling
        direct_dependency_ids=direct_dep_ids,
        skipped_entries=skipped_entries,
        warnings=warnings,
        parser_id="go_mod",
        format_version="1.0",
        fidelity=fidelity,
    )


class GoModParser(BaseDependencyParser):
    """Deterministic parser for Go modules implementing BaseDependencyParser."""

    @property
    def parser_id(self) -> str:
        return "go_mod"

    @property
    def ecosystem(self) -> str:
        return "Go"

    @property
    def supported_filenames(self) -> list[str]:
        return ["go.mod", "go.sum"]

    def parse(
        self,
        content: str | bytes,
        filename: str = "go.mod",
        secondary_content: str | bytes | None = None,
        secondary_filename: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ParsedGraph:
        lower_fn = filename.lower().strip()
        if not (lower_fn == "go.mod" or lower_fn.endswith(".mod")):
            raise DependencyParseError(
                f"Unsupported primary Go module format '{filename}'. Primary file must be 'go.mod'."
            )
        return parse_go_mod(
            content=content,
            filename=filename,
            secondary_content=secondary_content,
            secondary_filename=secondary_filename,
        )
