"""Unit tests for Python dependency parser covering poetry.lock, uv.lock, pylock.toml, and requirements.txt."""

import pytest

from vulnify.parsers.models import DependencyParseError, FidelityLevel
from vulnify.parsers.python import (
    PythonDependencyParser,
    parse_poetry_lock,
    parse_pylock_toml,
    parse_requirements_txt,
    parse_uv_lock,
)

SAMPLE_POETRY_LOCK = """
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:58cd2187c01e70e6e26505bca751777aa9f2f0b7f430da880e70d6172025376a"},
]

[package.dependencies]
certifi = ">=2017.4.17"
urllib3 = ">=1.21.1,<3"

[[package]]
name = "certifi"
version = "2023.7.22"
description = "Python package for providing Mozilla's CA Bundle."
optional = false
python-versions = ">=3.6"
files = []

[[package]]
name = "urllib3"
version = "2.0.4"
description = "HTTP library with thread-safe connection pooling, file post, and more."
optional = false
python-versions = ">=3.7"
files = []

[metadata]
lock-version = "2.0"
"""

SAMPLE_UV_LOCK = """
version = 1
revision = 1

[[package]]
name = "my-service"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "fastapi" },
]

[[package]]
name = "fastapi"
version = "0.115.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "starlette" },
    { name = "pydantic" },
]

[[package]]
name = "starlette"
version = "0.38.6"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pydantic"
version = "2.9.2"
source = { registry = "https://pypi.org/simple" }
"""

SAMPLE_PYLOCK_TOML = """
lock-version = "1.0"

[[packages]]
name = "flask"
version = "3.0.0"
dependencies = [
    { name = "werkzeug" },
]

[[packages]]
name = "werkzeug"
version = "3.0.1"
"""

SAMPLE_REQUIREMENTS_TXT = """
# Production requirements file
--extra-index-url https://pypi.org/simple
-r base-requirements.txt

requests==2.31.0
urllib3==2.0.7 ; python_version >= '3.8'

# Unpinned entries that should be reported with limitations
flask>=2.0.0
pytest
"""


def test_parse_poetry_lock() -> None:
    graph = parse_poetry_lock(SAMPLE_POETRY_LOCK)
    assert len(graph.packages) == 3
    pkg_ids = {p.id for p in graph.packages}
    assert "pypi:requests@2.31.0" in pkg_ids
    assert "pypi:certifi@2023.7.22" in pkg_ids
    assert "pypi:urllib3@2.0.4" in pkg_ids

    # Check purls
    req_pkg = next(p for p in graph.packages if p.name == "requests")
    assert req_pkg.purl == "pkg:pypi/requests@2.31.0"
    assert req_pkg.checksum is not None

    # requests is direct dependency; certifi & urllib3 are transitive
    assert "pypi:requests@2.31.0" in graph.direct_dependency_ids
    assert "pypi:certifi@2023.7.22" not in graph.direct_dependency_ids

    # Transitive dependency edges
    edge_pairs = {(e.source_id, e.target_id) for e in graph.edges}
    assert ("pypi:requests@2.31.0", "pypi:certifi@2023.7.22") in edge_pairs
    assert ("pypi:requests@2.31.0", "pypi:urllib3@2.0.4") in edge_pairs
    assert graph.fidelity == FidelityLevel.EXACT_LOCKFILE.value


def test_parse_uv_lock() -> None:
    graph = parse_uv_lock(SAMPLE_UV_LOCK)
    assert len(graph.packages) == 3  # fastapi, starlette, pydantic (my-service is virtual root)
    pkg_ids = {p.id for p in graph.packages}
    assert "pypi:fastapi@0.115.0" in pkg_ids
    assert "pypi:starlette@0.38.6" in pkg_ids
    assert "pypi:pydantic@2.9.2" in pkg_ids

    # fastapi is direct dependency from virtual root
    assert "pypi:fastapi@0.115.0" in graph.direct_dependency_ids
    assert "pypi:starlette@0.38.6" not in graph.direct_dependency_ids

    edge_pairs = {(e.source_id, e.target_id) for e in graph.edges}
    assert ("pypi:fastapi@0.115.0", "pypi:starlette@0.38.6") in edge_pairs
    assert ("pypi:fastapi@0.115.0", "pypi:pydantic@2.9.2") in edge_pairs
    assert graph.fidelity == FidelityLevel.EXACT_LOCKFILE.value


def test_parse_pylock_toml() -> None:
    graph = parse_pylock_toml(SAMPLE_PYLOCK_TOML)
    assert len(graph.packages) == 2
    pkg_ids = {p.id for p in graph.packages}
    assert "pypi:flask@3.0.0" in pkg_ids
    assert "pypi:werkzeug@3.0.1" in pkg_ids

    assert "pypi:flask@3.0.0" in graph.direct_dependency_ids
    edge_pairs = {(e.source_id, e.target_id) for e in graph.edges}
    assert ("pypi:flask@3.0.0", "pypi:werkzeug@3.0.1") in edge_pairs


def test_parse_requirements_txt() -> None:
    graph = parse_requirements_txt(SAMPLE_REQUIREMENTS_TXT)
    # Only 2 pinned entries: requests==2.31.0, urllib3==2.0.7
    assert len(graph.packages) == 2
    pkg_ids = {p.id for p in graph.packages}
    assert "pypi:requests@2.31.0" in pkg_ids
    assert "pypi:urllib3@2.0.7" in pkg_ids

    # Check environment marker preserved
    urllib3_pkg = next(p for p in graph.packages if p.name == "urllib3")
    assert urllib3_pkg.environment_markers == "python_version >= '3.8'"

    # requirements.txt fidelity is manifest_declared
    assert graph.fidelity == FidelityLevel.MANIFEST_DECLARED.value
    # Has warnings about unpinned packages (flask>=2.0.0, pytest) and CLI flags
    assert graph.skipped_entries >= 4
    warning_text = " ".join(graph.warnings).lower()
    assert "unpinned requirement" in warning_text
    assert "flask>=2.0.0" in warning_text
    assert "pytest" in warning_text


def test_python_unified_parser_dispatch() -> None:
    parser = PythonDependencyParser()
    assert parser.ecosystem == "PyPI"

    g_poetry = parser.parse(SAMPLE_POETRY_LOCK, "poetry.lock")
    assert g_poetry.parser_id == "poetry_lock"

    g_uv = parser.parse(SAMPLE_UV_LOCK, "uv.lock")
    assert g_uv.parser_id == "uv_lock"

    g_pylock = parser.parse(SAMPLE_PYLOCK_TOML, "pylock.toml")
    assert g_pylock.parser_id == "pylock_toml"

    g_req = parser.parse(SAMPLE_REQUIREMENTS_TXT, "requirements.txt")
    assert g_req.parser_id == "requirements_txt"

    with pytest.raises(DependencyParseError):
        parser.parse("{}", "unsupported.json")
