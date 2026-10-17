"""Backend-owned ecosystem capability registry and parser dispatcher."""

from functools import lru_cache
from typing import Any, Literal
from pydantic import BaseModel, Field

from vulnify.config import get_settings
from vulnify.parsers.cargo import CargoLockfileParser
from vulnify.parsers.golang import GoModParser
from vulnify.parsers.models import (
    BaseDependencyParser,
    DependencyParseError,
    FidelityLevel,
)
from vulnify.parsers.npm import NpmLockfileParser
from vulnify.parsers.python import PythonDependencyParser


class ImportFieldDefinition(BaseModel):
    """Specification of an input field required or accepted by an import method."""
    name: str = Field(..., description="Machine-readable field identifier")
    label: str = Field(..., description="Human-readable field label")
    type: Literal["string", "file", "boolean", "select"] = Field(..., description="Field data type")
    required: bool = Field(..., description="Whether this field is mandatory")
    description: str = Field(..., description="Field purpose and format guidance")
    placeholder: str | None = Field(default=None, description="Optional input placeholder")
    default_value: Any = Field(default=None, description="Optional default value")
    options: list[str] | None = Field(default=None, description="Options for select fields")


class ImportMethodCapability(BaseModel):
    """Specification of a concrete import method supported by an ecosystem."""
    id: str = Field(..., description="Stable method identifier")
    name: str = Field(..., description="Human-readable method name")
    description: str = Field(..., description="Method explanation")
    fidelity: FidelityLevel = Field(..., description="Dependency resolution fidelity classification")
    fidelity_description: str = Field(..., description="Explanation of resolution fidelity guarantees")
    accepted_filenames: list[str] = Field(..., description="Exact recognized filenames")
    accepted_extensions: list[str] = Field(..., description="Accepted file extensions")
    requires_paired_file: bool = Field(default=False, description="Whether a secondary file is mandatory")
    paired_file_name: str | None = Field(default=None, description="Expected secondary filename if applicable")
    paired_file_description: str | None = Field(default=None, description="Explanation of secondary file purpose")
    fields: list[ImportFieldDefinition] = Field(default_factory=list, description="Input fields required by this method")
    limitations: list[str] = Field(default_factory=list, description="Known limitations of this import method")


class EcosystemCapability(BaseModel):
    """Complete specification of a supported package ecosystem in Vulnify."""
    id: str = Field(..., description="Stable internal ecosystem identifier")
    display_name: str = Field(..., description="User-facing display name")
    osv_ecosystem: str = Field(..., description="Canonical OSV ecosystem identifier")
    supported_import_methods: list[ImportMethodCapability] = Field(..., description="Import methods implemented for this ecosystem")
    max_file_size_bytes: int = Field(..., description="Maximum accepted upload size in bytes")
    max_packages: int = Field(..., description="Maximum number of packages accepted per import")
    validation_rules: list[str] = Field(default_factory=list, description="Validation constraints enforced during parsing")
    limitations: list[str] = Field(default_factory=list, description="Ecosystem-level constraints and limitations")


class EcosystemCapabilitiesResponse(BaseModel):
    """API response model delivering all backend ecosystem capabilities."""
    supported_ecosystems: list[str] = Field(..., description="List of supported ecosystem identifiers")
    capabilities: list[EcosystemCapability] = Field(..., description="Detailed capability configurations")


class EcosystemRegistry:
    """Centralized backend registry defining all supported ecosystems and their parsers."""

    def __init__(self) -> None:
        settings = get_settings()
        max_size = settings.MAX_UPLOAD_SIZE_BYTES
        max_packages = settings.DEPENDENCY_IMPORT_MAX_PACKAGES

        # Reusable standard field definitions
        field_service_name = ImportFieldDefinition(
            name="service_name",
            label="Service Name",
            type="string",
            required=True,
            description="Named microservice or application component within the project (e.g. 'web-api', 'billing').",
            placeholder="e.g. payment-service",
        )
        field_primary_file = ImportFieldDefinition(
            name="file",
            label="Dependency File",
            type="file",
            required=True,
            description="Primary dependency lockfile or manifest.",
        )
        field_secondary_file = ImportFieldDefinition(
            name="secondary_file",
            label="Paired Checksum File (go.sum)",
            type="file",
            required=False,
            description="Optional paired go.sum file for cryptographic module verification.",
        )

        # 1. npm / JavaScript Ecosystem Capability
        npm_capability = EcosystemCapability(
            id="npm",
            display_name="npm (JavaScript / Node.js)",
            osv_ecosystem="npm",
            max_file_size_bytes=max_size,
            max_packages=max_packages,
            validation_rules=[
                "File must be valid UTF-8 JSON text.",
                "Must be an npm lockfile adhering to version 1, 2, or 3 schema.",
                "Package versions must be valid SemVer 2.0.0 representations.",
            ],
            limitations=[
                "Arbitrary package.json manifest files without resolved lockfileVersion are not accepted.",
                "Does not execute package lifecycle scripts, install scripts, or network requests.",
            ],
            supported_import_methods=[
                ImportMethodCapability(
                    id="npm_lockfile",
                    name="npm package-lock.json",
                    description="Extracts fully resolved package versions and dependency relationships from npm lockfiles (v1, v2, v3).",
                    fidelity=FidelityLevel.EXACT_LOCKFILE,
                    fidelity_description="Extracts exact resolved versions, package integrity hashes, and nested dependency edges.",
                    accepted_filenames=["package-lock.json", "npm-shrinkwrap.json"],
                    accepted_extensions=[".json"],
                    requires_paired_file=False,
                    fields=[field_service_name, field_primary_file],
                    limitations=[
                        "Requires lockfileVersion 1, 2, or 3.",
                        "Direct dependencies are derived from the root package definition.",
                    ],
                )
            ],
        )

        # 2. PyPI / Python Ecosystem Capability
        pypi_capability = EcosystemCapability(
            id="PyPI",
            display_name="PyPI (Python)",
            osv_ecosystem="PyPI",
            max_file_size_bytes=max_size,
            max_packages=max_packages,
            validation_rules=[
                "TOML lockfiles must conform to their respective specification.",
                "requirements.txt must be valid UTF-8 text.",
                "Package versions must satisfy PEP 440 grammar.",
            ],
            limitations=[
                "setup.py and unpinned pyproject.toml are not accepted because they do not contain resolved versions.",
                "requirements.txt files containing only unpinned ranges cannot guarantee exact resolution.",
            ],
            supported_import_methods=[
                ImportMethodCapability(
                    id="poetry_lock",
                    name="Poetry Lockfile (poetry.lock)",
                    description="Fully resolved Python dependency tree generated by Poetry.",
                    fidelity=FidelityLevel.EXACT_LOCKFILE,
                    fidelity_description="Extracts exact resolved versions, package hashes, and transitive dependency relationships.",
                    accepted_filenames=["poetry.lock"],
                    accepted_extensions=[".lock"],
                    requires_paired_file=False,
                    fields=[field_service_name, field_primary_file],
                    limitations=["Requires Poetry TOML format with [[package]] records."],
                ),
                ImportMethodCapability(
                    id="uv_lock",
                    name="uv Lockfile (uv.lock)",
                    description="Modern, high-performance Python dependency lockfile generated by Astral uv.",
                    fidelity=FidelityLevel.EXACT_LOCKFILE,
                    fidelity_description="Extracts exact resolved package versions and direct workspace dependencies.",
                    accepted_filenames=["uv.lock"],
                    accepted_extensions=[".lock"],
                    requires_paired_file=False,
                    fields=[field_service_name, field_primary_file],
                    limitations=["Requires standard uv TOML lockfile format."],
                ),
                ImportMethodCapability(
                    id="pylock_toml",
                    name="PEP 751 Lockfile (pylock.toml)",
                    description="Standardized Python dependency lockfile conforming to PEP 751.",
                    fidelity=FidelityLevel.EXACT_LOCKFILE,
                    fidelity_description="Extracts resolved package versions from standardized PEP 751 lockfile.",
                    accepted_filenames=["pylock.toml"],
                    accepted_extensions=[".toml"],
                    requires_paired_file=False,
                    fields=[field_service_name, field_primary_file],
                    limitations=["Requires PEP 751 compliant TOML format."],
                ),
                ImportMethodCapability(
                    id="requirements_txt",
                    name="Pinned Requirements (requirements.txt)",
                    description="Declared direct dependencies from a Python requirements file.",
                    fidelity=FidelityLevel.MANIFEST_DECLARED,
                    fidelity_description="Only strictly pinned entries (package==version) are imported. Transitive dependency resolution cannot be guaranteed.",
                    accepted_filenames=["requirements.txt"],
                    accepted_extensions=[".txt"],
                    requires_paired_file=False,
                    fields=[field_service_name, field_primary_file],
                    limitations=[
                        "Only strictly pinned entries (package==version) are imported.",
                        "Unpinned requirements (e.g. package>=1.0.0) are skipped with warnings.",
                        "Transitive dependencies are not recorded without a lockfile.",
                    ],
                ),
            ],
        )

        # 3. Cargo / Rust Ecosystem Capability
        cargo_capability = EcosystemCapability(
            id="Cargo",
            display_name="Cargo (Rust)",
            osv_ecosystem="crates.io",
            max_file_size_bytes=max_size,
            max_packages=max_packages,
            validation_rules=[
                "File must be valid UTF-8 TOML text.",
                "Must be a Cargo.lock file with [[package]] entries.",
                "Crate versions must adhere to SemVer 2.0.0.",
            ],
            limitations=[
                "Cargo.toml manifest files are not accepted without a resolved Cargo.lock.",
                "Does not execute cargo build or custom build scripts (build.rs).",
            ],
            supported_import_methods=[
                ImportMethodCapability(
                    id="cargo_lock",
                    name="Cargo Lockfile (Cargo.lock)",
                    description="Fully resolved dependency graph generated by Cargo.",
                    fidelity=FidelityLevel.EXACT_LOCKFILE,
                    fidelity_description="Extracts exact crate versions, checksums, and transitive dependency edges.",
                    accepted_filenames=["Cargo.lock"],
                    accepted_extensions=[".lock"],
                    requires_paired_file=False,
                    fields=[field_service_name, field_primary_file],
                    limitations=[
                        "Requires Cargo.lock format (v1, v2, v3, or v4).",
                        "Workspace root crates are used to identify direct service dependencies.",
                    ],
                )
            ],
        )

        # 4. Go / Golang Ecosystem Capability
        go_capability = EcosystemCapability(
            id="Go",
            display_name="Go (Golang)",
            osv_ecosystem="Go",
            max_file_size_bytes=max_size,
            max_packages=max_packages,
            validation_rules=[
                "Must be a valid UTF-8 go.mod file with module and require clauses.",
                "Paired go.sum file, if provided, must contain valid module checksum lines.",
                "Versions must be valid Go module semantic versions (vX.Y.Z).",
            ],
            limitations=[
                "Direct vs indirect dependencies are extracted from go.mod comments (// indirect).",
                "Full inter-module transitive tree resolution requires Go toolchain calculation.",
            ],
            supported_import_methods=[
                ImportMethodCapability(
                    id="go_mod",
                    name="Go Module (go.mod with optional go.sum)",
                    description="Go module dependencies from go.mod with optional paired checksum verification from go.sum.",
                    fidelity=FidelityLevel.EXACT_LOCKFILE,
                    fidelity_description="Extracts module versions, distinguishes direct from indirect dependencies, and verifies module checksums if go.sum is supplied.",
                    accepted_filenames=["go.mod"],
                    accepted_extensions=[".mod"],
                    requires_paired_file=False,
                    paired_file_name="go.sum",
                    paired_file_description="Optional paired go.sum file for cryptographic module verification.",
                    fields=[field_service_name, field_primary_file, field_secondary_file],
                    limitations=[
                        "go.mod provides declared module requirements.",
                        "Module checksum verification is performed only when paired go.sum is provided.",
                    ],
                )
            ],
        )

        self._capabilities: dict[str, EcosystemCapability] = {
            "npm": npm_capability,
            "pypi": pypi_capability,
            "cargo": cargo_capability,
            "go": go_capability,
        }

        # Canonical capitalization mapping (case-insensitive lookup -> canonical key)
        self._canonical_id_map: dict[str, str] = {
            "npm": "npm",
            "node": "npm",
            "javascript": "npm",
            "pypi": "PyPI",
            "python": "PyPI",
            "cargo": "Cargo",
            "rust": "Cargo",
            "crates.io": "Cargo",
            "go": "Go",
            "golang": "Go",
        }

        # Parsers
        self._parsers: dict[str, BaseDependencyParser] = {
            "npm": NpmLockfileParser(),
            "pypi": PythonDependencyParser(),
            "cargo": CargoLockfileParser(),
            "go": GoModParser(),
        }

    def get_capabilities(self) -> list[EcosystemCapability]:
        """Return list of all registered ecosystem capabilities."""
        return list(self._capabilities.values())

    def get_supported_ecosystem_ids(self) -> list[str]:
        """Return the canonical ecosystem IDs advertised by the registry."""
        return [cap.id for cap in self._capabilities.values()]

    def get_canonical_ecosystem_name(self, name: str) -> str | None:
        """Resolve a loose or case-insensitive ecosystem name to its canonical identifier."""
        if not name or not isinstance(name, str):
            return None
        return self._canonical_id_map.get(name.strip().lower())

    def get_capability(self, ecosystem_name: str) -> EcosystemCapability | None:
        """Retrieve the capability model for the specified ecosystem name."""
        canonical = self.get_canonical_ecosystem_name(ecosystem_name)
        if not canonical:
            return None
        return self._capabilities.get(canonical.lower())

    def get_osv_ecosystem(self, ecosystem_name: str) -> str:
        """Retrieve the canonical OSV ecosystem identifier for an ecosystem name.
        
        Raises DependencyParseError if the ecosystem is not recognized.
        """
        cap = self.get_capability(ecosystem_name)
        if not cap:
            raise DependencyParseError(
                f"Unsupported ecosystem '{ecosystem_name}': cannot resolve canonical OSV ecosystem identifier."
            )
        return cap.osv_ecosystem

    def get_parser(self, ecosystem_name: str) -> BaseDependencyParser:
        """Retrieve the parser instance for the specified ecosystem."""
        canonical = self.get_canonical_ecosystem_name(ecosystem_name)
        if not canonical or canonical.lower() not in self._parsers:
            raise DependencyParseError(
                f"No implemented dependency parser for ecosystem '{ecosystem_name}'."
            )
        return self._parsers[canonical.lower()]

    def resolve_import_method(
        self,
        ecosystem_name: str,
        filename: str,
        method_id: str | None = None,
    ) -> ImportMethodCapability:
        """Resolve the appropriate import method for an uploaded file and ecosystem.
        
        Raises DependencyParseError with clear format guidance if no matching method is found.
        """
        cap = self.get_capability(ecosystem_name)
        if not cap:
            raise DependencyParseError(
                f"Project ecosystem '{ecosystem_name}' is not supported for dependency import. "
                f"Supported ecosystems: {', '.join(self.get_supported_ecosystem_ids())}."
            )

        lower_fn = filename.lower().strip()

        # If method_id was explicitly requested, validate it
        if method_id:
            for m in cap.supported_import_methods:
                if m.id.lower() == method_id.lower().strip():
                    # Validate that filename matches accepted formats
                    matched_file = any(lower_fn == af.lower() for af in m.accepted_filenames)
                    matched_ext = any(lower_fn.endswith(ext.lower()) for ext in m.accepted_extensions)
                    if not (matched_file or matched_ext):
                        raise DependencyParseError(
                            f"File '{filename}' does not match expected format for method '{m.name}'. "
                            f"Accepted formats: {', '.join(m.accepted_filenames)}."
                        )
                    return m
            raise DependencyParseError(
                f"Import method '{method_id}' is not supported for ecosystem '{cap.id}'. "
                f"Available methods: {', '.join(m.id for m in cap.supported_import_methods)}."
            )

        # Auto-detect method from filename
        for m in cap.supported_import_methods:
            if any(lower_fn == af.lower() for af in m.accepted_filenames):
                return m

        for m in cap.supported_import_methods:
            if any(lower_fn.endswith(ext.lower()) for ext in m.accepted_extensions):
                return m

        # No matching method found
        all_accepted: list[str] = []
        for m in cap.supported_import_methods:
            all_accepted.extend(m.accepted_filenames)
        accepted_str = ", ".join(all_accepted)
        raise DependencyParseError(
            f"Unsupported lockfile format '{filename}' is not currently supported for ecosystem '{cap.id}'. "
            f"Supported file formats: {accepted_str}."
        )


@lru_cache
def get_ecosystem_registry() -> EcosystemRegistry:
    """Return the singleton instance of the ecosystem capability registry."""
    return EcosystemRegistry()


def get_supported_ecosystem_ids() -> list[str]:
    """Helper returning canonical ecosystem identifiers."""
    return get_ecosystem_registry().get_supported_ecosystem_ids()
