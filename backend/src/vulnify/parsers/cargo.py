"""Deterministic parser for Rust Cargo.lock files without code execution."""

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
    if isinstance(content, bytes):
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DependencyParseError("Malformed file: Cargo.lock must be valid UTF-8 encoded text.") from exc
    return content


def parse_cargo_lock(content: str | bytes, filename: str = "Cargo.lock") -> ParsedGraph:
    """Parse a Cargo.lock file deterministically via standard tomllib."""
    content_str = _decode_content(content)
    if not content_str.strip():
        raise DependencyParseError("Cargo.lock content is empty.")

    try:
        data = tomllib.loads(content_str)
    except tomllib.TOMLDecodeError as exc:
        raise DependencyParseError(f"Malformed Cargo.lock: invalid TOML syntax: {exc}") from exc

    raw_packages = data.get("package") or []
    if not isinstance(raw_packages, list) or len(raw_packages) == 0:
        return ParsedGraph(
            packages=[],
            edges=[],
            direct_dependency_ids=[],
            skipped_entries=0,
            warnings=["Cargo.lock contains no package records."],
            parser_id="cargo_lock",
            format_version=str(data.get("version", "unknown")),
            fidelity=FidelityLevel.EXACT_LOCKFILE.value,
        )

    unique_packages: dict[str, ParsedPackageVersion] = {}
    packages_by_name: dict[str, list[tuple[str, str, list[str]]]] = {}
    workspace_direct_dep_specs: list[str] = []
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
        version = raw_version.strip()
        source = pkg.get("source")
        checksum = str(pkg["checksum"]).strip() if "checksum" in pkg and pkg["checksum"] else None

        raw_deps = pkg.get("dependencies") or []
        deps_list: list[str] = [str(d).strip() for d in raw_deps if str(d).strip()] if isinstance(raw_deps, list) else []

        # In Cargo.lock, packages with NO `source` are local workspace/root crates
        is_workspace_root = source is None or not str(source).strip()

        if is_workspace_root:
            workspace_direct_dep_specs.extend(deps_list)
            # The root crate itself is the service, not an external dependency
            continue

        pv_id = f"cargo:{pkg_name}@{version}"
        purl = f"pkg:cargo/{pkg_name}@{version}"

        pv = PackageVersion(
            id=pv_id,
            name=pkg_name,
            version=version,
            ecosystem="crates.io",
            purl=purl,
            checksum=checksum,
            source_url=str(source).strip() if source else None,
        )
        unique_packages[pv_id] = pv
        packages_by_name.setdefault(pkg_name, []).append((pv_id, version, deps_list))

    def _resolve_dep_spec(dep_spec: str) -> str | None:
        """Resolve dependency string e.g. 'serde 1.0.197 (registry+...)' or 'serde'."""
        parts = dep_spec.split()
        dep_name = parts[0].strip()
        dep_ver = parts[1].strip() if len(parts) > 1 else None

        candidates = packages_by_name.get(dep_name, [])
        if not candidates:
            return None

        if dep_ver:
            for c_id, c_ver, _ in candidates:
                if c_ver == dep_ver:
                    return c_id

        # Fallback to first matching candidate
        return candidates[0][0]

    # Resolve direct dependencies
    direct_dep_ids: set[str] = set()
    for spec in workspace_direct_dep_specs:
        target_id = _resolve_dep_spec(spec)
        if target_id:
            direct_dep_ids.add(target_id)

    # Resolve transitive dependency edges
    edges: set[tuple[str, str]] = set()
    depended_on_ids: set[str] = set()

    for pkg_name, versions in packages_by_name.items():
        for src_id, _, deps_list in versions:
            for dep_spec in deps_list:
                dst_id = _resolve_dep_spec(dep_spec)
                if dst_id and dst_id != src_id:
                    edges.add((src_id, dst_id))
                    depended_on_ids.add(dst_id)

    # If no workspace root crate was found, fallback to packages with in-degree 0
    if not direct_dep_ids:
        direct_dep_ids = {pv_id for pv_id in unique_packages if pv_id not in depended_on_ids}

    # If still empty, use all unique packages
    if not direct_dep_ids and unique_packages:
        direct_dep_ids = set(unique_packages.keys())

    edge_models = [
        ParsedDependencyEdge(source_id=src, target_id=dst, direct=False)
        for src, dst in edges
    ]

    return ParsedGraph(
        packages=list(unique_packages.values()),
        edges=edge_models,
        direct_dependency_ids=sorted(direct_dep_ids),
        skipped_entries=skipped_entries,
        warnings=warnings,
        parser_id="cargo_lock",
        format_version=str(data.get("version", "unknown")),
        fidelity=FidelityLevel.EXACT_LOCKFILE.value,
    )


class CargoLockfileParser(BaseDependencyParser):
    """Deterministic parser for Rust Cargo.lock files implementing BaseDependencyParser."""

    @property
    def parser_id(self) -> str:
        return "cargo_lock"

    @property
    def ecosystem(self) -> str:
        return "Cargo"

    @property
    def supported_filenames(self) -> list[str]:
        return ["Cargo.lock"]

    def parse(
        self,
        content: str | bytes,
        filename: str = "Cargo.lock",
        secondary_content: str | bytes | None = None,
        secondary_filename: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ParsedGraph:
        return parse_cargo_lock(content, filename=filename)
