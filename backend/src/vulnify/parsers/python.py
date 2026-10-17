"""Deterministic parsers for Python dependency inputs without code execution.

Supports:
- poetry.lock (Poetry TOML lockfile)
- uv.lock (uv modern TOML lockfile)
- pylock.toml (PEP 751 TOML lockfile)
- requirements.txt (Pinned requirements manifest)
"""

import re
import tomllib
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
    """Decode bytes or string safely into UTF-8 text."""
    if isinstance(content, bytes):
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DependencyParseError("Malformed file: file must be valid UTF-8 encoded text.") from exc
    return content


def parse_poetry_lock(content: str | bytes, filename: str = "poetry.lock") -> ParsedGraph:
    """Parse a Poetry poetry.lock file deterministically via standard tomllib."""
    content_str = _decode_content(content)
    if not content_str.strip():
        raise DependencyParseError("Lockfile content is empty.")

    try:
        data = tomllib.loads(content_str)
    except tomllib.TOMLDecodeError as exc:
        raise DependencyParseError(f"Malformed poetry.lock: invalid TOML syntax: {exc}") from exc

    raw_packages = data.get("package") or data.get("packages") or []
    if not isinstance(raw_packages, list) or len(raw_packages) == 0:
        return ParsedGraph(
            packages=[],
            edges=[],
            direct_dependency_ids=[],
            skipped_entries=0,
            warnings=["poetry.lock contains no package records."],
            parser_id="poetry_lock",
            format_version=str(data.get("metadata", {}).get("lock-version", "unknown")),
            fidelity=FidelityLevel.EXACT_LOCKFILE.value,
        )

    unique_packages: dict[str, ParsedPackageVersion] = {}
    packages_by_name: dict[str, tuple[str, dict[str, Any]]] = {}
    skipped_entries = 0
    warnings: list[str] = []

    for pkg in raw_packages:
        if not isinstance(pkg, dict):
            skipped_entries += 1
            continue

        raw_name = pkg.get("name")
        raw_version = pkg.get("version")

        if not raw_name or not isinstance(raw_name, str) or not raw_name.strip():
            skipped_entries += 1
            warnings.append("Skipping package entry: missing or empty package name.")
            continue

        if not raw_version or not isinstance(raw_version, str) or not raw_version.strip():
            skipped_entries += 1
            warnings.append(f"Skipping package '{raw_name}': missing resolved version.")
            continue

        pkg_name = raw_name.strip()
        canonical_name = pkg_name.lower().replace("_", "-")
        version = raw_version.strip()
        pv_id = f"pypi:{canonical_name}@{version}"
        purl = f"pkg:pypi/{canonical_name}@{version}"

        # Extract optional checksum/files metadata
        files = pkg.get("files") or []
        checksum = None
        if isinstance(files, list) and files:
            first_file = files[0]
            if isinstance(first_file, dict) and "hash" in first_file:
                checksum = str(first_file["hash"]).strip()

        pv = PackageVersion(
            id=pv_id,
            name=canonical_name,
            version=version,
            ecosystem="PyPI",
            purl=purl,
            checksum=checksum,
        )
        unique_packages[pv_id] = pv

        deps = pkg.get("dependencies") or {}
        if not isinstance(deps, dict):
            deps = {}
        packages_by_name[canonical_name] = (pv_id, deps)

    # Calculate dependency edges and compute in-degrees to identify direct dependencies
    edges: set[tuple[str, str]] = set()
    depended_on_names: set[str] = set()

    for canonical_name, (src_id, deps_dict) in packages_by_name.items():
        for req_raw_name in deps_dict.keys():
            if not isinstance(req_raw_name, str):
                continue
            req_canonical = req_raw_name.strip().lower().replace("_", "-")
            if req_canonical in packages_by_name:
                dst_id = packages_by_name[req_canonical][0]
                if src_id != dst_id:
                    edges.add((src_id, dst_id))
                    depended_on_names.add(req_canonical)

    # In poetry.lock, root packages are packages not depended upon by any other package in the lockfile
    direct_dependency_ids = [
        packages_by_name[name][0]
        for name in packages_by_name
        if name not in depended_on_names
    ]

    # If all packages are depended on (e.g. cycle), treat all packages as candidates
    if not direct_dependency_ids and unique_packages:
        direct_dependency_ids = list(unique_packages.keys())

    edge_models = [
        ParsedDependencyEdge(source_id=src, target_id=dst, direct=False)
        for src, dst in edges
    ]

    lock_version = str(data.get("metadata", {}).get("lock-version", "unknown"))

    return ParsedGraph(
        packages=list(unique_packages.values()),
        edges=edge_models,
        direct_dependency_ids=direct_dependency_ids,
        skipped_entries=skipped_entries,
        warnings=warnings,
        parser_id="poetry_lock",
        format_version=lock_version,
        fidelity=FidelityLevel.EXACT_LOCKFILE.value,
    )


def parse_uv_lock(content: str | bytes, filename: str = "uv.lock") -> ParsedGraph:
    """Parse a uv.lock file deterministically via standard tomllib."""
    content_str = _decode_content(content)
    if not content_str.strip():
        raise DependencyParseError("Lockfile content is empty.")

    try:
        data = tomllib.loads(content_str)
    except tomllib.TOMLDecodeError as exc:
        raise DependencyParseError(f"Malformed uv.lock: invalid TOML syntax: {exc}") from exc

    raw_packages = data.get("package") or data.get("packages") or []
    if not isinstance(raw_packages, list) or len(raw_packages) == 0:
        return ParsedGraph(
            packages=[],
            edges=[],
            direct_dependency_ids=[],
            skipped_entries=0,
            warnings=["uv.lock contains no package records."],
            parser_id="uv_lock",
            format_version=str(data.get("version", "unknown")),
            fidelity=FidelityLevel.EXACT_LOCKFILE.value,
        )

    unique_packages: dict[str, ParsedPackageVersion] = {}
    packages_by_name: dict[str, tuple[str, list[str]]] = {}
    workspace_direct_dep_names: set[str] = set()
    skipped_entries = 0
    warnings: list[str] = []

    for pkg in raw_packages:
        if not isinstance(pkg, dict):
            skipped_entries += 1
            continue

        raw_name = pkg.get("name")
        if not raw_name or not isinstance(raw_name, str) or not raw_name.strip():
            skipped_entries += 1
            warnings.append("Skipping package entry: missing or empty package name.")
            continue

        canonical_name = raw_name.strip().lower().replace("_", "-")
        source = pkg.get("source") or {}

        # Detect workspace root / virtual root package
        is_virtual_root = (
            isinstance(source, dict)
            and (source.get("virtual") == "." or source.get("editable") == ".")
        ) or pkg.get("root") is True

        deps_list: list[str] = []
        raw_deps = pkg.get("dependencies") or []
        if isinstance(raw_deps, list):
            for d in raw_deps:
                if isinstance(d, dict) and "name" in d:
                    deps_list.append(str(d["name"]).strip().lower().replace("_", "-"))
                elif isinstance(d, str):
                    # string may be "pkg==1.0" or "pkg"
                    dep_name_match = re.match(r"^([a-zA-Z0-9_\-\.]+)", d.strip())
                    if dep_name_match:
                        deps_list.append(dep_name_match.group(1).lower().replace("_", "-"))

        if is_virtual_root:
            workspace_direct_dep_names.update(deps_list)
            # The workspace package itself is the service, not an external dependency
            continue

        raw_version = pkg.get("version")
        if not raw_version or not isinstance(raw_version, str) or not raw_version.strip():
            skipped_entries += 1
            warnings.append(f"Skipping package '{canonical_name}': missing resolved version.")
            continue

        version = raw_version.strip()
        pv_id = f"pypi:{canonical_name}@{version}"
        purl = f"pkg:pypi/{canonical_name}@{version}"

        pv = PackageVersion(
            id=pv_id,
            name=canonical_name,
            version=version,
            ecosystem="PyPI",
            purl=purl,
        )
        unique_packages[pv_id] = pv
        packages_by_name[canonical_name] = (pv_id, deps_list)

    # Build edges
    edges: set[tuple[str, str]] = set()
    depended_on_names: set[str] = set()

    for canonical_name, (src_id, dep_names) in packages_by_name.items():
        for req_canonical in dep_names:
            if req_canonical in packages_by_name:
                dst_id = packages_by_name[req_canonical][0]
                if src_id != dst_id:
                    edges.add((src_id, dst_id))
                    depended_on_names.add(req_canonical)

    if workspace_direct_dep_names:
        direct_dependency_ids = [
            packages_by_name[name][0]
            for name in workspace_direct_dep_names
            if name in packages_by_name
        ]
    else:
        # Fallback to packages with in-degree 0
        direct_dependency_ids = [
            packages_by_name[name][0]
            for name in packages_by_name
            if name not in depended_on_names
        ]

    if not direct_dependency_ids and unique_packages:
        direct_dependency_ids = list(unique_packages.keys())

    edge_models = [
        ParsedDependencyEdge(source_id=src, target_id=dst, direct=False)
        for src, dst in edges
    ]

    return ParsedGraph(
        packages=list(unique_packages.values()),
        edges=edge_models,
        direct_dependency_ids=direct_dependency_ids,
        skipped_entries=skipped_entries,
        warnings=warnings,
        parser_id="uv_lock",
        format_version=str(data.get("version", "unknown")),
        fidelity=FidelityLevel.EXACT_LOCKFILE.value,
    )


def parse_pylock_toml(content: str | bytes, filename: str = "pylock.toml") -> ParsedGraph:
    """Parse a PEP 751 pylock.toml lockfile deterministically."""
    content_str = _decode_content(content)
    if not content_str.strip():
        raise DependencyParseError("Lockfile content is empty.")

    try:
        data = tomllib.loads(content_str)
    except tomllib.TOMLDecodeError as exc:
        raise DependencyParseError(f"Malformed pylock.toml: invalid TOML syntax: {exc}") from exc

    raw_packages = data.get("packages") or data.get("package") or []
    if not isinstance(raw_packages, list) or len(raw_packages) == 0:
        return ParsedGraph(
            packages=[],
            edges=[],
            direct_dependency_ids=[],
            skipped_entries=0,
            warnings=["pylock.toml contains no package records."],
            parser_id="pylock_toml",
            format_version=str(data.get("lock-version", "unknown")),
            fidelity=FidelityLevel.EXACT_LOCKFILE.value,
        )

    unique_packages: dict[str, ParsedPackageVersion] = {}
    packages_by_name: dict[str, tuple[str, list[str]]] = {}
    skipped_entries = 0
    warnings: list[str] = []

    for pkg in raw_packages:
        if not isinstance(pkg, dict):
            skipped_entries += 1
            continue

        raw_name = pkg.get("name")
        raw_version = pkg.get("version")

        if not raw_name or not isinstance(raw_name, str) or not raw_name.strip():
            skipped_entries += 1
            warnings.append("Skipping package entry: missing or empty package name.")
            continue

        if not raw_version or not isinstance(raw_version, str) or not raw_version.strip():
            skipped_entries += 1
            warnings.append(f"Skipping package '{raw_name}': missing resolved version.")
            continue

        canonical_name = raw_name.strip().lower().replace("_", "-")
        version = raw_version.strip()
        pv_id = f"pypi:{canonical_name}@{version}"
        purl = f"pkg:pypi/{canonical_name}@{version}"

        pv = PackageVersion(
            id=pv_id,
            name=canonical_name,
            version=version,
            ecosystem="PyPI",
            purl=purl,
        )
        unique_packages[pv_id] = pv

        deps_list: list[str] = []
        raw_deps = pkg.get("dependencies") or []
        if isinstance(raw_deps, list):
            for d in raw_deps:
                if isinstance(d, dict) and "name" in d:
                    deps_list.append(str(d["name"]).strip().lower().replace("_", "-"))
                elif isinstance(d, str):
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)", d.strip())
                    if m:
                        deps_list.append(m.group(1).lower().replace("_", "-"))

        packages_by_name[canonical_name] = (pv_id, deps_list)

    edges: set[tuple[str, str]] = set()
    depended_on_names: set[str] = set()

    for canonical_name, (src_id, dep_names) in packages_by_name.items():
        for req_canonical in dep_names:
            if req_canonical in packages_by_name:
                dst_id = packages_by_name[req_canonical][0]
                if src_id != dst_id:
                    edges.add((src_id, dst_id))
                    depended_on_names.add(req_canonical)

    direct_dependency_ids = [
        packages_by_name[name][0]
        for name in packages_by_name
        if name not in depended_on_names
    ]

    if not direct_dependency_ids and unique_packages:
        direct_dependency_ids = list(unique_packages.keys())

    edge_models = [
        ParsedDependencyEdge(source_id=src, target_id=dst, direct=False)
        for src, dst in edges
    ]

    return ParsedGraph(
        packages=list(unique_packages.values()),
        edges=edge_models,
        direct_dependency_ids=direct_dependency_ids,
        skipped_entries=skipped_entries,
        warnings=warnings,
        parser_id="pylock_toml",
        format_version=str(data.get("lock-version", "unknown")),
        fidelity=FidelityLevel.EXACT_LOCKFILE.value,
    )


def parse_requirements_txt(content: str | bytes, filename: str = "requirements.txt") -> ParsedGraph:
    """Parse a requirements.txt file, safely extracting pinned dependencies with clear limitations."""
    content_str = _decode_content(content)
    if not content_str.strip():
        raise DependencyParseError("Requirements file is empty.")

    unique_packages: dict[str, ParsedPackageVersion] = {}
    skipped_entries = 0
    warnings: list[str] = [
        "requirements.txt provides declared dependencies; transitive dependency relationships are not recorded."
    ]

    lines = content_str.splitlines()

    for line_num, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Skip CLI flags and includes (-r, -i, -f, -c, --extra-index-url, etc.)
        if line.startswith("-"):
            warnings.append(f"Line {line_num}: skipping CLI flag or include directive '{line}'.")
            skipped_entries += 1
            continue

        # Split off environment markers (e.g. requests==2.31.0 ; python_version >= '3.10')
        parts = line.split(";", 1)
        spec = parts[0].strip()
        marker = parts[1].strip() if len(parts) > 1 else None

        # Look for strictly pinned entry: package==version
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.\+]+)", spec)
        if match:
            raw_name = match.group(1).strip()
            version = match.group(2).strip()
            canonical_name = raw_name.lower().replace("_", "-")
            pv_id = f"pypi:{canonical_name}@{version}"
            purl = f"pkg:pypi/{canonical_name}@{version}"

            if pv_id not in unique_packages:
                unique_packages[pv_id] = PackageVersion(
                    id=pv_id,
                    name=canonical_name,
                    version=version,
                    ecosystem="PyPI",
                    purl=purl,
                    environment_markers=marker,
                )
        else:
            # Unpinned entry (e.g. package>=1.0.0, package~=2.1, or bare package)
            skipped_entries += 1
            warnings.append(
                f"Line {line_num}: skipping unpinned requirement '{spec}'. "
                "Only pinned dependencies (name==version) provide verifiable exact versions."
            )

    direct_ids = list(unique_packages.keys())

    return ParsedGraph(
        packages=list(unique_packages.values()),
        edges=[],  # requirements.txt does not provide transitive dependency edges
        direct_dependency_ids=direct_ids,
        skipped_entries=skipped_entries,
        warnings=warnings,
        parser_id="requirements_txt",
        format_version="1.0",
        fidelity=FidelityLevel.MANIFEST_DECLARED.value,
    )


class PythonDependencyParser(BaseDependencyParser):
    """Unified parser for Python dependency inputs."""

    @property
    def parser_id(self) -> str:
        return "python_dependency_parser"

    @property
    def ecosystem(self) -> str:
        return "PyPI"

    @property
    def supported_filenames(self) -> list[str]:
        return ["poetry.lock", "uv.lock", "pylock.toml", "requirements.txt"]

    def parse(
        self,
        content: str | bytes,
        filename: str,
        secondary_content: str | bytes | None = None,
        secondary_filename: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ParsedGraph:
        lower_fn = filename.lower().strip()
        if lower_fn == "poetry.lock" or lower_fn.endswith(".poetry.lock"):
            return parse_poetry_lock(content, filename=filename)
        elif lower_fn == "uv.lock" or lower_fn.endswith(".uv.lock"):
            return parse_uv_lock(content, filename=filename)
        elif lower_fn == "pylock.toml" or lower_fn.endswith(".pylock.toml"):
            return parse_pylock_toml(content, filename=filename)
        elif lower_fn == "requirements.txt" or lower_fn.endswith(".requirements.txt") or lower_fn.endswith("-requirements.txt"):
            return parse_requirements_txt(content, filename=filename)
        else:
            raise DependencyParseError(
                f"Unsupported Python dependency file format: '{filename}'. "
                "Supported formats for PyPI projects are: poetry.lock, uv.lock, pylock.toml, requirements.txt."
            )
