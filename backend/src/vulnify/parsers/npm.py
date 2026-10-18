"""Deterministic parser for npm package-lock.json files (v1, v2, and v3)."""

import json
from typing import Any
from vulnify.parsers.models import (
    LockfileParseError,
    ParsedDependencyEdge,
    ParsedGraph,
    ParsedPackageVersion,
)


def _looks_like_package_manifest(data: dict[str, Any]) -> bool:
    if "lockfileVersion" in data or isinstance(data.get("packages"), dict):
        return False
    # Pre-npm-5 shrinkwraps lack lockfileVersion but still map names to resolved records (dicts).
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = data.get(key)
        if isinstance(section, dict) and section and not any(isinstance(v, dict) for v in section.values()):
            return True
    return False


def parse_npm_lockfile(content: str | bytes, filename: str = "package-lock.json") -> ParsedGraph:
    """Parse an npm package-lock.json file without code execution.
    
    Supports lockfileVersion 1, 2, and 3. Extracts resolved PackageVersions,
    direct service dependencies, and transitive dependency edges.
    """
    if isinstance(content, bytes):
        try:
            content_str = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LockfileParseError("Malformed lockfile: file must be valid UTF-8 encoded text.") from exc
    else:
        content_str = content

    if not content_str.strip():
        raise LockfileParseError("Lockfile content is empty.")

    try:
        data: Any = json.loads(content_str)
    except json.JSONDecodeError as exc:
        raise LockfileParseError(f"Malformed lockfile: invalid JSON syntax at line {exc.lineno}, column {exc.colno}.") from exc

    if not isinstance(data, dict):
        raise LockfileParseError("Invalid lockfile format: root must be a JSON object.")

    if _looks_like_package_manifest(data):
        raise LockfileParseError(
            f"'{filename}' is not an npm lockfile: it has no 'lockfileVersion' and lists version ranges "
            "instead of resolved versions (package.json manifest). Upload package-lock.json or npm-shrinkwrap.json."
        )

    unique_packages: dict[str, ParsedPackageVersion] = {}
    edges: set[tuple[str, str]] = set()
    direct_dep_ids: set[str] = set()
    skipped_entries = 0
    warnings: list[str] = []

    # Check for npm v2/v3 'packages' key
    if "packages" in data and isinstance(data["packages"], dict):
        packages_dict = data["packages"]
        root_package = packages_dict.get("", {})
        direct_dep_names: set[str] = set()
        if isinstance(root_package, dict):
            deps = root_package.get("dependencies", {})
            if isinstance(deps, dict):
                direct_dep_names.update(deps.keys())
            dev_deps = root_package.get("devDependencies", {})
            if isinstance(dev_deps, dict):
                direct_dep_names.update(dev_deps.keys())

        # Collect all resolved package nodes
        # path_key -> (id, name, version, purl, dependencies_dict)
        packages_by_path: dict[str, tuple[str, str, str, str, dict[str, str]]] = {}

        for path_key, pkg_info in packages_dict.items():
            if path_key == "":
                continue

            if not isinstance(pkg_info, dict):
                skipped_entries += 1
                continue

            # Extract package name
            pkg_name: str | None = None
            if "name" in pkg_info and isinstance(pkg_info["name"], str) and pkg_info["name"].strip():
                pkg_name = pkg_info["name"].strip()
            else:
                parts = path_key.split("node_modules/")
                candidate = parts[-1].strip()
                if candidate:
                    pkg_name = candidate

            if not pkg_name:
                skipped_entries += 1
                warnings.append(f"Skipping entry at '{path_key}': unable to determine package name.")
                continue

            # Extract resolved version
            version_val = pkg_info.get("version")
            if not version_val or not isinstance(version_val, str) or not version_val.strip():
                skipped_entries += 1
                warnings.append(f"Skipping package '{pkg_name}' at '{path_key}': missing resolved version.")
                continue

            version = version_val.strip()
            pv_id = f"npm:{pkg_name}@{version}"
            purl = f"pkg:npm/{pkg_name}@{version}"

            dependencies = pkg_info.get("dependencies", {})
            if not isinstance(dependencies, dict):
                dependencies = {}

            packages_by_path[path_key] = (pv_id, pkg_name, version, purl, dependencies)
            if pv_id not in unique_packages:
                unique_packages[pv_id] = ParsedPackageVersion(
                    id=pv_id,
                    name=pkg_name,
                    version=version,
                    ecosystem="npm",
                    purl=purl,
                )

        # Resolve direct dependencies to PackageVersion IDs
        for dep_name in direct_dep_names:
            top_path = f"node_modules/{dep_name}"
            if top_path in packages_by_path:
                direct_dep_ids.add(packages_by_path[top_path][0])
            else:
                # Fallback: match any package by name
                for p_info in packages_by_path.values():
                    if p_info[1] == dep_name:
                        direct_dep_ids.add(p_info[0])
                        break

        # Resolve transitive dependency edges
        for path_key, (src_id, pkg_name, _, _, deps_dict) in packages_by_path.items():
            for req_name in deps_dict.keys():
                if not isinstance(req_name, str):
                    continue
                req_name = req_name.strip()
                target_id: str | None = None

                # 1. Check nested node_modules inside current package
                nested_path = f"{path_key}/node_modules/{req_name}"
                if nested_path in packages_by_path:
                    target_id = packages_by_path[nested_path][0]
                elif f"node_modules/{req_name}" in packages_by_path:
                    target_id = packages_by_path[f"node_modules/{req_name}"][0]
                else:
                    for p_info in packages_by_path.values():
                        if p_info[1] == req_name:
                            target_id = p_info[0]
                            break

                if target_id and target_id != src_id:
                    edges.add((src_id, target_id))

    # Fallback to v1 dependencies tree if packages was absent or empty
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        def _parse_v1_tree(tree: dict[str, Any], parent_id: str | None = None) -> None:
            nonlocal skipped_entries
            for pkg_name, dep_info in tree.items():
                if not isinstance(dep_info, dict):
                    skipped_entries += 1
                    warnings.append(f"Skipping v1 dependency '{pkg_name}': entry is not a resolved lockfile record.")
                    continue

                version_val = dep_info.get("version")
                if not version_val or not isinstance(version_val, str) or not version_val.strip():
                    skipped_entries += 1
                    warnings.append(f"Skipping v1 dependency '{pkg_name}': missing resolved version.")
                    continue

                version = version_val.strip()
                pv_id = f"npm:{pkg_name}@{version}"
                purl = f"pkg:npm/{pkg_name}@{version}"

                if pv_id not in unique_packages:
                    unique_packages[pv_id] = ParsedPackageVersion(
                        id=pv_id,
                        name=pkg_name,
                        version=version,
                        ecosystem="npm",
                        purl=purl,
                    )

                if parent_id is None:
                    direct_dep_ids.add(pv_id)
                else:
                    if parent_id != pv_id:
                        edges.add((parent_id, pv_id))

                sub_deps = dep_info.get("dependencies")
                if isinstance(sub_deps, dict):
                    _parse_v1_tree(sub_deps, parent_id=pv_id)

        _parse_v1_tree(data["dependencies"])
    else:
        # Empty lockfile or no dependencies
        warnings.append("Lockfile contains no package records.")

    edge_models = [
        ParsedDependencyEdge(source_id=src, target_id=dst, direct=False)
        for src, dst in edges
    ]

    lockfile_ver = str(data.get("lockfileVersion", "1")) if isinstance(data, dict) else "unknown"

    return ParsedGraph(
        packages=list(unique_packages.values()),
        edges=edge_models,
        direct_dependency_ids=list(direct_dep_ids),
        skipped_entries=skipped_entries,
        warnings=warnings,
        parser_id="npm_lockfile",
        format_version=lockfile_ver,
        fidelity="exact_lockfile",
    )


from vulnify.parsers.models import BaseDependencyParser


class NpmLockfileParser(BaseDependencyParser):
    """Deterministic parser for npm lockfiles implementing BaseDependencyParser."""

    @property
    def parser_id(self) -> str:
        return "npm_lockfile"

    @property
    def ecosystem(self) -> str:
        return "npm"

    @property
    def supported_filenames(self) -> list[str]:
        return ["package-lock.json", "npm-shrinkwrap.json"]

    def parse(
        self,
        content: str | bytes,
        filename: str = "package-lock.json",
        secondary_content: str | bytes | None = None,
        secondary_filename: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ParsedGraph:
        return parse_npm_lockfile(content, filename=filename)

