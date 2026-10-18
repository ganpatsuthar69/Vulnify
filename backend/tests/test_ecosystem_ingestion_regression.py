"""Regression tests that every supported ecosystem delivers its parsed packages to the OSV scan.

Covers the US-103 failure class (packages silently lost between import and scan) for PyPI, Cargo and Go.
"""

import hashlib
import uuid
from typing import Any

import pytest
from httpx import AsyncClient

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.graph.advisory_repository import FalkorAdvisoryRepository
from vulnify.graph.dependency_repository import FalkorDependencyRepository
from vulnify.graph.job_repository import InMemoryIngestionJobRepository
from vulnify.graph.project_repository import InMemoryProjectRepository, FalkorProjectRepository
from vulnify.models import JobStatus, JobType
from vulnify.parsers.cargo import parse_cargo_lock
from vulnify.parsers.golang import parse_go_mod
from vulnify.parsers.models import ParsedGraph
from vulnify.parsers.python import (
    parse_poetry_lock,
    parse_pylock_toml,
    parse_requirements_txt,
    parse_uv_lock,
)

GO_MOD_DIRECT_INDIRECT = """module example.com/shop/api

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/text v0.14.0
)

require (
\tgithub.com/go-playground/validator/v10 v10.14.0 // indirect
\tgolang.org/x/net v1.2.0 // indirect
)
"""

REQUIREMENTS_MIXED = """# pinned, with extras and markers
uvicorn[standard]==0.30.0
Flask==2.0.1
zope.interface==5.5.0
typing_extensions==4.9.0 ; python_version < '3.12'
requests>=2.0.0
django==3.2.*
"""


@pytest.fixture(autouse=True)
def seed_admin_user(mock_user_repo) -> None:
    mock_user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    user = mock_user_repo.get_by_email(ADMIN_USER["email"])
    if user:
        user.id = ADMIN_USER["id"]
        mock_user_repo._users_by_id[ADMIN_USER["id"]] = user


# ---------------------------------------------------------------------
# Parser level
# ---------------------------------------------------------------------

def test_go_mod_keeps_indirect_modules_as_imported_packages() -> None:
    parsed = parse_go_mod(GO_MOD_DIRECT_INDIRECT)
    assert {(p.name, p.version) for p in parsed.packages} == {
        ("github.com/gin-gonic/gin", "v1.9.1"),
        ("golang.org/x/text", "v0.14.0"),
        ("github.com/go-playground/validator/v10", "v10.14.0"),
        ("golang.org/x/net", "v1.2.0"),
    }
    # indirect modules must not be advertised as direct requires
    assert parsed.direct_dependency_ids == [
        "golang:github.com/gin-gonic/gin@v1.9.1",
        "golang:golang.org/x/text@v0.14.0",
    ]


def test_requirements_txt_accepts_extras_and_markers_and_rejects_wildcards() -> None:
    parsed = parse_requirements_txt(REQUIREMENTS_MIXED)
    assert {(p.name, p.version) for p in parsed.packages} == {
        ("uvicorn", "0.30.0"),
        ("flask", "2.0.1"),
        ("zope-interface", "5.5.0"),
        ("typing-extensions", "4.9.0"),
    }
    # the previously fabricated value would have been "3.2." for django==3.2.*
    assert all("*" not in p.version for p in parsed.packages)
    assert "typing-extensions" == parsed.packages[3].name
    assert parsed.packages[3].environment_markers == "python_version < '3.12'"
    joined = " ".join(parsed.warnings)
    assert "wildcard pinned requirement" in joined
    assert "skipping unpinned requirement 'requests>=2.0.0'" in joined
    assert parsed.skipped_entries == 2


def test_requirements_txt_counts_a_hash_continuation_once() -> None:
    content = "requests==2.31.0 --hash=sha256:abc \\\n    --hash=sha256:def\n"
    parsed = parse_requirements_txt(content)
    assert [(p.name, p.version) for p in parsed.packages] == [("requests", "2.31.0")]
    assert parsed.skipped_entries == 0


@pytest.mark.parametrize(
    ("parser", "filename", "content"),
    [
        (parse_poetry_lock, "poetry.lock", '[metadata]\nlock-version = "2.0"\n'),
        (parse_uv_lock, "uv.lock", "version = 1\n"),
        (parse_cargo_lock, "Cargo.lock", "version = 3\n"),
        (parse_requirements_txt, "requirements.txt", "requests>=2.0.0\nflask\n"),
        (parse_go_mod, "go.mod", "module example.com/x\n\ngo 1.21\n"),
    ],
)
def test_parsers_report_zero_packages_rather_than_a_silent_empty_graph(
    parser: Any, filename: str, content: str
) -> None:
    parsed = parser(content, filename=filename) if parser is not parse_go_mod else parser(content)
    assert parsed.packages == []
    assert parsed.direct_dependency_ids == []


# ---------------------------------------------------------------------
# Import endpoint level
# ---------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ecosystem", "filename", "content"),
    [
        ("PyPI", "poetry.lock", '[metadata]\nlock-version = "2.0"\n'),
        ("PyPI", "uv.lock", "version = 1\n"),
        ("PyPI", "requirements.txt", "requests>=2.0.0\ndjango\n"),
        ("Cargo", "Cargo.lock", "version = 3\n"),
        ("Go", "go.mod", "module example.com/x\n\ngo 1.21\n"),
    ],
)
async def test_import_endpoint_fails_loudly_for_empty_lockfiles_in_every_ecosystem(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
    mock_job_repo: InMemoryIngestionJobRepository,
    ecosystem: str,
    filename: str,
    content: str,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.create_project(name=f"Empty {ecosystem}", ecosystem=ecosystem, description="")

    res = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={"service_name": "svc", "filename": filename, "content": content},
    )

    assert res.status_code == 422
    assert "No resolved package versions found" in res.json().get("message", "")
    jobs, _, _ = mock_job_repo.list_jobs(project.id, job_type=JobType.DEPENDENCY_IMPORT)
    assert [j.status for j in jobs] == [JobStatus.FAILED]
    assert jobs[0].error_summary


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ecosystem", "filename", "content"),
    [
        ("PyPI", "pyproject.toml", '[project]\nname = "demo"\nversion = "0.1.0"\n'),
        ("PyPI", "Pipfile.lock", '{"default": {}}'),
        ("Cargo", "Cargo.toml", '[package]\nname = "demo"\nversion = "0.1.0"\n'),
        ("Go", "go.sum", "example.com/mod v1.0.0 h1:abc=\n"),
    ],
)
async def test_import_endpoint_rejects_unsupported_manifests_in_every_ecosystem(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
    mock_job_repo: InMemoryIngestionJobRepository,
    ecosystem: str,
    filename: str,
    content: str,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.create_project(name=f"Reject {ecosystem}", ecosystem=ecosystem, description="")

    res = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={"service_name": "svc", "filename": filename, "content": content},
    )

    assert res.status_code == 422
    assert filename in res.json().get("message", "") or "not supported" in res.json().get("message", "")
    jobs, _, _ = mock_job_repo.list_jobs(project.id, job_type=JobType.DEPENDENCY_IMPORT)
    # A rejected file must never leave a completed import behind.
    assert all(j.status != JobStatus.SUCCEEDED for j in jobs)


# ---------------------------------------------------------------------
# FalkorDB: imported packages must be reachable by the scanner
# ---------------------------------------------------------------------

def _suffix_name(base: str, suffix: str) -> str:
    return f"{base}-{suffix}"


def _go_graph(suffix: str) -> str:
    return (
        "module example.com/shop/api\n\ngo 1.21\n\n"
        "require (\n"
        f"\texample.com/shop/{_suffix_name('direct-mod', suffix)} v1.9.1\n"
        ")\n\n"
        "require (\n"
        f"\texample.com/shop/{_suffix_name('indirect-mod', suffix)} v0.4.0 // indirect\n"
        ")\n"
    )


def _poetry_graph(suffix: str) -> str:
    return (
        "[[package]]\n"
        f'name = "{_suffix_name("root-pkg", suffix)}"\n'
        'version = "1.0.0"\n\n'
        "[[package]]\n"
        f'name = "{_suffix_name("leaf-pkg", suffix)}"\n'
        'version = "2.1.0"\n\n'
        "[metadata]\n"
        'lock-version = "2.0"\n'
    )


def _uv_graph(suffix: str) -> str:
    return (
        "version = 1\n\n"
        "[[package]]\n"
        'name = "demo-service"\n'
        'version = "0.1.0"\n'
        'source = { virtual = "." }\n\n'
        "[[package]]\n"
        f'name = "{_suffix_name("workspace-pkg", suffix)}"\n'
        'version = "1.4.2"\n\n'
        "[[package]]\n"
        f'name = "{_suffix_name("orphan-pkg", suffix)}"\n'
        'version = "0.2.0"\n'
    )


def _cargo_graph(suffix: str) -> str:
    registry = 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    return (
        "version = 3\n\n"
        "[[package]]\n"
        'name = "demo-app"\n'
        'version = "0.1.0"\n\n'
        "[[package]]\n"
        f'name = "{_suffix_name("root-crate", suffix)}"\n'
        'version = "1.0.197"\n' + registry + "\n"
        "[[package]]\n"
        f'name = "{_suffix_name("leaf-crate", suffix)}"\n'
        'version = "0.2.5"\n' + registry + "\n"
    )


def _pylock_graph(suffix: str) -> str:
    return (
        'lock-version = "1.0"\n'
        'created-by = "regression"\n\n'
        "[[packages]]\n"
        f'name = "{_suffix_name("pylock-pkg", suffix)}"\n'
        'version = "3.1.2"\n'
    )


def _requirements_graph(suffix: str) -> str:
    return f"{_suffix_name('pinned-pkg', suffix)}==1.2.3\nrange-pkg>=1.0.0\n"


@pytest.fixture
def falkor_db():
    from vulnify.graph.client import get_graph_client

    try:
        client = get_graph_client()
        client.get_graph().query("RETURN 1")
        return client
    except Exception as exc:
        pytest.skip(f"FalkorDB is not reachable: {exc}")


@pytest.mark.parametrize(
    ("ecosystem", "filename", "builder", "parser"),
    [
        ("Go", "go.mod", _go_graph, parse_go_mod),
        ("PyPI", "poetry.lock", _poetry_graph, parse_poetry_lock),
        ("PyPI", "uv.lock", _uv_graph, parse_uv_lock),
        ("PyPI", "pylock.toml", _pylock_graph, parse_pylock_toml),
        ("PyPI", "requirements.txt", _requirements_graph, parse_requirements_txt),
        ("Cargo", "Cargo.lock", _cargo_graph, parse_cargo_lock),
    ],
)
@pytest.mark.asyncio
async def test_every_imported_package_is_discovered_by_the_scan(
    falkor_db, ecosystem: str, filename: str, builder: Any, parser: Any
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service_name = f"svc-{suffix}"
    graph = falkor_db.get_graph()

    project = FalkorProjectRepository(client=falkor_db).create_project(
        name=f"Ecosystem Discovery {suffix}", ecosystem=ecosystem, description="scan reachability"
    )
    service_id = f"{project.id}:{service_name}"

    content = builder(suffix)
    parsed = parser(content.encode(), filename=filename)

    try:
        summary = FalkorDependencyRepository(client=falkor_db).import_dependencies(
            project_id=project.id,
            service_name=service_name,
            filename=filename,
            sha256_hash=hashlib.sha256(content.encode()).hexdigest(),
            parsed_graph=parsed,
        )
        assert summary.packages_parsed == len(parsed.packages) > 0

        discovered = FalkorAdvisoryRepository(client=falkor_db).get_project_package_versions(project.id)
        assert {p.id for p in discovered} == {p.id for p in parsed.packages}, (
            "imported packages must all be reachable by the OSV scan"
        )

        # Inventory membership must not be presented as a dependency path.
        for pkg in parsed.packages:
            rel = graph.query(
                "MATCH (s:Service {id: $sid})-[r]->(pv:PackageVersion {id: $pid}) RETURN type(r) AS t, r.direct AS d",
                {"sid": service_id, "pid": pkg.id},
            ).result_set
            types = {row[0] for row in rel}
            assert "DEPENDS_ON" in types or "INCLUDES" in types
            if "INCLUDES" in types:
                includes = [row for row in rel if row[0] == "INCLUDES"]
                assert all(row[1] is None for row in includes)
    finally:
        for query, params in (
            ("MATCH (s:Service {id: $sid})-[:IMPORTED_FROM]->(ie:ImportEvent) DETACH DELETE ie", {"sid": service_id}),
            ("MATCH (s:Service {id: $sid}) DETACH DELETE s", {"sid": service_id}),
            ("MATCH (pv:PackageVersion) WHERE pv.id CONTAINS $suffix DETACH DELETE pv", {"suffix": suffix}),
            ("MATCH (p:Project {id: $pid}) DETACH DELETE p", {"pid": project.id}),
        ):
            try:
                graph.query(query, params)
            except Exception:
                pass


@pytest.mark.asyncio
async def test_go_indirect_module_is_scanned_but_not_claimed_as_direct_exposure(falkor_db) -> None:
    suffix = uuid.uuid4().hex[:8]
    graph = falkor_db.get_graph()
    project = FalkorProjectRepository(client=falkor_db).create_project(
        name=f"Go Indirect {suffix}", ecosystem="Go", description="indirect reachability"
    )
    service_name = f"api-{suffix}"
    service_id = f"{project.id}:{service_name}"
    content = _go_graph(suffix)

    try:
        parsed = parse_go_mod(content)
        FalkorDependencyRepository(client=falkor_db).import_dependencies(
            project_id=project.id,
            service_name=service_name,
            filename="go.mod",
            sha256_hash=hashlib.sha256(content.encode()).hexdigest(),
            parsed_graph=parsed,
        )

        discovered = FalkorAdvisoryRepository(client=falkor_db).get_project_package_versions(project.id)
        assert len(discovered) == 2

        indirect_id = next(p.id for p in parsed.packages if p.name.endswith("indirect-mod-" + suffix))
        direct_id = next(p.id for p in parsed.packages if p.name.endswith("direct-mod-" + suffix))

        # Findings traverse DEPENDS_ON paths only, so the indirect module is not reported as reached.
        paths = graph.query(
            "MATCH path = (s:Service {id: $sid})-[:DEPENDS_ON*1..8]->(pv:PackageVersion) RETURN pv.id AS id",
            {"sid": service_id},
        ).result_set
        assert [row[0] for row in paths] == [direct_id]
        assert indirect_id not in {row[0] for row in paths}
    finally:
        for query, params in (
            ("MATCH (s:Service {id: $sid})-[:IMPORTED_FROM]->(ie:ImportEvent) DETACH DELETE ie", {"sid": service_id}),
            ("MATCH (s:Service {id: $sid}) DETACH DELETE s", {"sid": service_id}),
            ("MATCH (pv:PackageVersion) WHERE pv.id CONTAINS $suffix DETACH DELETE pv", {"suffix": suffix}),
            ("MATCH (p:Project {id: $pid}) DETACH DELETE p", {"pid": project.id}),
        ):
            try:
                graph.query(query, params)
            except Exception:
                pass


def test_pypi_dotted_name_still_matches_its_advisory() -> None:
    """A dotted PyPI name must not be reported as NOT_AFFECTED purely because of spelling."""
    from vulnify.version_matching.models import AdvisoryData, MatchStatus, OSVAffectedPackage, OSVRange, OSVRangeEvent
    from vulnify.version_matching.range_evaluator import evaluate_version_against_advisory

    advisory = AdvisoryData(
        id="TEST-PYPI-DOTTED",
        affected=[
            OSVAffectedPackage(
                package_name="zope.interface",
                ecosystem="PyPI",
                ranges=[
                    OSVRange(
                        type="ECOSYSTEM",
                        events=[OSVRangeEvent(introduced="5.0.0"), OSVRangeEvent(fixed="6.0.0")],
                    )
                ],
            )
        ],
    )
    result = evaluate_version_against_advisory("zope-interface", "5.5.0", "PyPI", advisory)
    assert result.status == MatchStatus.AFFECTED
