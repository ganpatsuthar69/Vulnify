"""Tests for the typed backend-owned ecosystem capability registry."""

import pytest

from vulnify.parsers.models import DependencyParseError, FidelityLevel
from vulnify.parsers.registry import (
    EcosystemCapability,
    EcosystemRegistry,
    get_ecosystem_registry,
    get_supported_ecosystem_ids,
)


def test_registry_singleton_and_supported_ids() -> None:
    reg1 = get_ecosystem_registry()
    reg2 = get_ecosystem_registry()
    assert reg1 is reg2

    eco_ids = get_supported_ecosystem_ids()
    assert "npm" in eco_ids
    assert "PyPI" in eco_ids
    assert "Cargo" in eco_ids
    assert "Go" in eco_ids


def test_capabilities_structure_and_contracts() -> None:
    registry = get_ecosystem_registry()
    caps = registry.get_capabilities()
    assert len(caps) >= 4

    cap_by_id = {c.id: c for c in caps}

    # 1. npm Capability
    npm_cap = cap_by_id["npm"]
    assert npm_cap.display_name == "npm (JavaScript / Node.js)"
    assert npm_cap.osv_ecosystem == "npm"
    assert npm_cap.max_file_size_bytes > 0
    assert npm_cap.max_packages > 0
    assert len(npm_cap.supported_import_methods) >= 1
    npm_method = npm_cap.supported_import_methods[0]
    assert npm_method.id == "npm_lockfile"
    assert npm_method.fidelity == FidelityLevel.EXACT_LOCKFILE
    assert "package-lock.json" in npm_method.accepted_filenames

    # 2. PyPI Capability
    pypi_cap = cap_by_id["PyPI"]
    assert pypi_cap.display_name == "PyPI (Python)"
    assert pypi_cap.osv_ecosystem == "PyPI"
    method_ids = {m.id for m in pypi_cap.supported_import_methods}
    assert "poetry_lock" in method_ids
    assert "uv_lock" in method_ids
    assert "pylock_toml" in method_ids
    assert "requirements_txt" in method_ids

    # Check requirements_txt fidelity is manifest_declared
    req_method = next(m for m in pypi_cap.supported_import_methods if m.id == "requirements_txt")
    assert req_method.fidelity == FidelityLevel.MANIFEST_DECLARED
    assert len(req_method.limitations) > 0

    # 3. Cargo Capability
    cargo_cap = cap_by_id["Cargo"]
    assert cargo_cap.display_name == "Cargo (Rust)"
    assert cargo_cap.osv_ecosystem == "crates.io"
    assert len(cargo_cap.supported_import_methods) >= 1
    assert "Cargo.lock" in cargo_cap.supported_import_methods[0].accepted_filenames

    # 4. Go Capability
    go_cap = cap_by_id["Go"]
    assert go_cap.display_name == "Go (Golang)"
    assert go_cap.osv_ecosystem == "Go"
    go_method = go_cap.supported_import_methods[0]
    assert go_method.id == "go_mod"
    assert "go.mod" in go_method.accepted_filenames
    assert go_method.paired_file_name == "go.sum"


def test_canonical_name_resolution() -> None:
    registry = get_ecosystem_registry()
    assert registry.get_canonical_ecosystem_name("npm") == "npm"
    assert registry.get_canonical_ecosystem_name("NPM") == "npm"
    assert registry.get_canonical_ecosystem_name("pypi") == "PyPI"
    assert registry.get_canonical_ecosystem_name("python") == "PyPI"
    assert registry.get_canonical_ecosystem_name("cargo") == "Cargo"
    assert registry.get_canonical_ecosystem_name("rust") == "Cargo"
    assert registry.get_canonical_ecosystem_name("crates.io") == "Cargo"
    assert registry.get_canonical_ecosystem_name("go") == "Go"
    assert registry.get_canonical_ecosystem_name("golang") == "Go"
    assert registry.get_canonical_ecosystem_name("unknown-eco") is None


def test_resolve_import_method_success_and_failure() -> None:
    registry = get_ecosystem_registry()

    # Auto-detection
    m_npm = registry.resolve_import_method("npm", "package-lock.json")
    assert m_npm.id == "npm_lockfile"

    m_poetry = registry.resolve_import_method("PyPI", "poetry.lock")
    assert m_poetry.id == "poetry_lock"

    m_uv = registry.resolve_import_method("PyPI", "uv.lock")
    assert m_uv.id == "uv_lock"

    m_pylock = registry.resolve_import_method("PyPI", "pylock.toml")
    assert m_pylock.id == "pylock_toml"

    m_req = registry.resolve_import_method("PyPI", "requirements.txt")
    assert m_req.id == "requirements_txt"

    m_cargo = registry.resolve_import_method("Cargo", "Cargo.lock")
    assert m_cargo.id == "cargo_lock"

    m_go = registry.resolve_import_method("Go", "go.mod")
    assert m_go.id == "go_mod"

    # Incompatible format for ecosystem
    with pytest.raises(DependencyParseError) as exc_info:
        registry.resolve_import_method("npm", "poetry.lock")
    assert "Unsupported lockfile format" in str(exc_info.value)
    assert "npm" in str(exc_info.value)

    # Incompatible explicit method ID
    with pytest.raises(DependencyParseError) as exc_info:
        registry.resolve_import_method("PyPI", "poetry.lock", method_id="npm_lockfile")
    assert "not supported for ecosystem 'PyPI'" in str(exc_info.value)

    # Unsupported ecosystem
    with pytest.raises(DependencyParseError) as exc_info:
        registry.resolve_import_method("unsupported_eco", "any.lock")
    assert "not supported" in str(exc_info.value)


def test_osv_ecosystem_resolution() -> None:
    registry = get_ecosystem_registry()
    assert registry.get_osv_ecosystem("npm") == "npm"
    assert registry.get_osv_ecosystem("PyPI") == "PyPI"
    assert registry.get_osv_ecosystem("python") == "PyPI"
    assert registry.get_osv_ecosystem("Cargo") == "crates.io"
    assert registry.get_osv_ecosystem("rust") == "crates.io"
    assert registry.get_osv_ecosystem("Go") == "Go"

    with pytest.raises(DependencyParseError):
        registry.get_osv_ecosystem("unsupported-lang")
