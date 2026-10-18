"""Regression tests for US-103: zero-package OSV scans must not be reported as successful."""

import hashlib
import json
import uuid
from typing import Any

import httpx
import pytest
from httpx import AsyncClient

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.config import Settings
from vulnify.graph.advisory_repository import InMemoryAdvisoryRepository, PackageVersionItem
from vulnify.graph.job_repository import InMemoryIngestionJobRepository
from vulnify.graph.project_repository import InMemoryProjectRepository
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.models import JobStatus, JobType
from vulnify.osv.cache import OsvCache
from vulnify.osv.client import OsvClient
from vulnify.osv.models import OsvPackage, OsvQuery, parse_osv_vulnerability
from vulnify.osv.service import OsvService
from vulnify.parsers.models import LockfileParseError
from vulnify.parsers.npm import parse_npm_lockfile

SECRET = "test_session_secret_that_is_at_least_32_chars_long!"

PACKAGE_JSON_MANIFEST = {
    "name": "billing-app",
    "version": "1.0.0",
    "dependencies": {"left-pad": "^1.3.0", "tiny-lib": "~2.0.0"},
    "devDependencies": {"test-runner": ">=3.0.0"},
}


def _synthetic_vuln(vuln_id: str, package_name: str) -> dict[str, Any]:
    return {
        "id": vuln_id,
        "summary": f"Synthetic advisory for {package_name}",
        "details": "Synthetic test record.",
        "modified": "2024-01-02T00:00:00Z",
        "published": "2024-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"name": package_name, "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
            }
        ],
    }


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "SESSION_SECRET": SECRET,
        "OSV_ENABLED": True,
        "OSV_API_BASE_URL": "http://osv.test",
        "OSV_API_MAX_RETRIES": 0,
        "OSV_API_BACKOFF_BASE_SECONDS": 0.01,
    }
    base.update(overrides)
    return Settings(**base)


def _pkg(name: str, version: str, ecosystem: str = "npm") -> PackageVersionItem:
    return PackageVersionItem(
        id=f"{ecosystem}:{name}@{version}", name=name, version=version, ecosystem=ecosystem, purl=""
    )


def _query(name: str, version: str) -> OsvQuery:
    return OsvQuery(package=OsvPackage(name=name, ecosystem="npm"), version=version)


class StubOsvClient:
    """Records the queries it receives and returns canned per-query results."""

    def __init__(self, results: dict[OsvQuery, list[Any]] | None = None, failures: dict[OsvQuery, str] | None = None):
        self.results = results or {}
        self.failures = failures or {}
        self.calls: list[list[OsvQuery]] = []

    async def query_batch(self, queries: list[OsvQuery], **_: Any):
        self.calls.append(list(queries))
        res = {q: self.results[q] for q in queries if q in self.results}
        fails = [(q, self.failures[q]) for q in queries if q in self.failures]
        return res, fails


@pytest.fixture(autouse=True)
def seed_admin_user(mock_user_repo: InMemoryUserRepository) -> None:
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
# Package discovery
# ---------------------------------------------------------------------

def test_parser_rejects_package_json_manifest() -> None:
    with pytest.raises(LockfileParseError, match="not an npm lockfile"):
        parse_npm_lockfile(json.dumps(PACKAGE_JSON_MANIFEST).encode(), filename="package.json")


def test_parser_accepts_legacy_shrinkwrap_without_lockfile_version() -> None:
    legacy = {
        "name": "legacy-app",
        "version": "1.0.0",
        "dependencies": {"left-pad": {"version": "1.3.0"}, "tiny-lib": {"version": "2.0.1"}},
    }
    parsed = parse_npm_lockfile(json.dumps(legacy).encode(), filename="npm-shrinkwrap.json")
    found = {(p.name, p.version) for p in parsed.packages}
    assert found == {("left-pad", "1.3.0"), ("tiny-lib", "2.0.1")}


def test_parser_extracts_exact_versions_from_v3_lockfile() -> None:
    lockfile = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"left-pad": "^1.3.0"}},
            "node_modules/left-pad": {"version": "1.3.0", "dependencies": {"tiny-lib": "^2.0.0"}},
            "node_modules/tiny-lib": {"version": "2.0.1"},
        },
    }
    parsed = parse_npm_lockfile(json.dumps(lockfile).encode(), filename="package-lock.json")
    assert {(p.name, p.version, p.ecosystem) for p in parsed.packages} == {
        ("left-pad", "1.3.0", "npm"),
        ("tiny-lib", "2.0.1", "npm"),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("filename", "content", "expected"),
    [
        ("package.json", PACKAGE_JSON_MANIFEST, "not an npm lockfile"),
        ("package-lock.json", {"lockfileVersion": 3, "packages": {"": {"name": "empty-app"}}}, "No resolved package versions"),
    ],
)
async def test_import_endpoint_rejects_inputs_without_packages(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
    mock_job_repo: InMemoryIngestionJobRepository,
    filename: str,
    content: dict[str, Any],
    expected: str,
) -> None:
    authenticate_client(client)
    project = mock_project_repo.create_project(name="Regression Import", ecosystem="npm", description="")

    res = await client.post(
        f"/api/projects/{project.id}/dependencies/import",
        json={"service_name": "billing-svc", "filename": filename, "content": json.dumps(content)},
    )

    assert res.status_code == 422
    assert expected in res.json().get("message", "")
    jobs, _, _ = mock_job_repo.list_jobs(project.id, job_type=JobType.DEPENDENCY_IMPORT)
    assert len(jobs) == 1
    assert jobs[0].status == JobStatus.FAILED
    assert jobs[0].error_summary


# ---------------------------------------------------------------------
# Zero-result scans and skipped packages
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_zero_package_scan_is_not_reported_as_completed() -> None:
    repo = InMemoryAdvisoryRepository()
    jobs = InMemoryIngestionJobRepository()
    stub = StubOsvClient()
    service = OsvService(settings=_settings(), advisory_repo=repo, client=stub, cache=OsvCache(300), job_repo=jobs)

    summary = await service.import_project_advisories("proj-empty")

    assert summary.status == "skipped"
    assert summary.total_package_versions == 0
    assert summary.eligible_package_versions == 0
    assert "nothing was scanned" in summary.errors[0]
    assert stub.calls == []
    job = jobs.get_job("proj-empty", summary.job_id)
    assert job is not None
    assert job.status == JobStatus.FAILED
    assert job.processed_items == 0


@pytest.mark.asyncio
async def test_all_packages_skipped_reports_reasons_and_makes_no_requests() -> None:
    repo = InMemoryAdvisoryRepository()
    repo.set_project_packages(
        "proj-skip",
        [
            _pkg("range-lib", "^1.0.0"),
            PackageVersionItem(id="npm:no-version@", name="no-version", version="", ecosystem="npm", purl=""),
            _pkg("alien-lib", "1.0.0", ecosystem="not-a-real-ecosystem"),
        ],
    )
    stub = StubOsvClient()
    service = OsvService(settings=_settings(), advisory_repo=repo, client=stub, cache=OsvCache(300))

    summary = await service.import_project_advisories("proj-skip")

    assert summary.status == "skipped"
    assert summary.skipped_packages == 3
    assert stub.calls == []
    assert [r.outcome for r in summary.package_results] == ["skipped"] * 3
    assert all(r.reason for r in summary.package_results)
    assert "range" in summary.package_results[0].reason
    assert "version" in summary.package_results[1].reason.lower()
    assert "not supported" in summary.package_results[2].reason


@pytest.mark.asyncio
async def test_every_package_gets_an_outcome_and_counters_add_up() -> None:
    repo = InMemoryAdvisoryRepository()
    repo.set_project_packages(
        "proj-mixed",
        [_pkg("vuln-lib", "1.0.0"), _pkg("clean-lib", "2.0.0"), _pkg("flaky-lib", "3.0.0"), _pkg("range-lib", "~4.0.0")],
    )
    vuln = parse_osv_vulnerability(_synthetic_vuln("TEST-OSV-1", "vuln-lib"), retrieved_at=1700000000)
    stub = StubOsvClient(
        results={_query("vuln-lib", "1.0.0"): [vuln], _query("clean-lib", "2.0.0"): []},
        failures={_query("flaky-lib", "3.0.0"): "OSV query failed with status 500"},
    )
    service = OsvService(settings=_settings(), advisory_repo=repo, client=stub, cache=OsvCache(300))

    summary = await service.import_project_advisories("proj-mixed")

    outcomes = {r.name: r for r in summary.package_results}
    assert outcomes["vuln-lib"].outcome == "advisories_found"
    assert outcomes["vuln-lib"].advisory_ids == ["TEST-OSV-1"]
    assert outcomes["clean-lib"].outcome == "no_advisories"
    assert outcomes["flaky-lib"].outcome == "query_failed"
    assert "500" in outcomes["flaky-lib"].reason
    assert outcomes["range-lib"].outcome == "skipped"

    assert summary.status == "partial_failure"
    assert summary.total_package_versions == 4
    assert summary.eligible_package_versions == 3
    assert (
        summary.packages_with_advisories
        + summary.packages_with_no_advisories
        + summary.failed_lookups
        + summary.skipped_packages
        == summary.total_package_versions
    )
    assert summary.advisories_found == 1
    assert summary.relationships_created == 1
    linked = repo.get_project_advisories("proj-mixed")
    assert [(a["id"], a["package_name"]) for a in linked] == [("TEST-OSV-1", "vuln-lib")]


@pytest.mark.asyncio
async def test_query_missing_from_client_response_is_a_failure_not_clean() -> None:
    repo = InMemoryAdvisoryRepository()
    repo.set_project_packages("proj-gap", [_pkg("ghost-lib", "1.0.0")])
    service = OsvService(settings=_settings(), advisory_repo=repo, client=StubOsvClient(), cache=OsvCache(300))

    summary = await service.import_project_advisories("proj-gap")

    assert summary.status == "failed"
    assert summary.packages_with_no_advisories == 0
    assert summary.package_results[0].outcome == "query_failed"


# ---------------------------------------------------------------------
# API failures and caching
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_total_api_failure_is_failed_and_not_cached() -> None:
    repo = InMemoryAdvisoryRepository()
    repo.set_project_packages("proj-down", [_pkg("a-lib", "1.0.0"), _pkg("b-lib", "1.0.0")])
    cache = OsvCache(300)
    stub = StubOsvClient(
        failures={_query("a-lib", "1.0.0"): "timeout", _query("b-lib", "1.0.0"): "timeout"},
    )
    jobs = InMemoryIngestionJobRepository()
    service = OsvService(settings=_settings(), advisory_repo=repo, client=stub, cache=cache, job_repo=jobs)

    summary = await service.import_project_advisories("proj-down")

    assert summary.status == "failed"
    assert summary.failed_lookups == 2
    assert summary.packages_with_no_advisories == 0
    assert cache.get("npm", "a-lib", "1.0.0") is None
    assert cache.get("npm", "b-lib", "1.0.0") is None
    assert jobs.get_job("proj-down", summary.job_id).status == JobStatus.FAILED


@pytest.mark.asyncio
async def test_cache_hits_skip_requests_and_force_refresh_bypasses_cache() -> None:
    repo = InMemoryAdvisoryRepository()
    repo.set_project_packages("proj-cache", [_pkg("clean-lib", "2.0.0")])
    stub = StubOsvClient(results={_query("clean-lib", "2.0.0"): []})
    service = OsvService(settings=_settings(), advisory_repo=repo, client=stub, cache=OsvCache(300))

    first = await service.import_project_advisories("proj-cache")
    second = await service.import_project_advisories("proj-cache")
    third = await service.import_project_advisories("proj-cache", force_refresh=True)

    assert first.status == second.status == third.status == "completed"
    assert (first.cache_hits, second.cache_hits, third.cache_hits) == (0, 1, 0)
    assert len(stub.calls) == 2
    assert second.package_results[0].outcome == "no_advisories"


# ---------------------------------------------------------------------
# OSV HTTP requests
# ---------------------------------------------------------------------

def _mock_osv_client(handler) -> tuple[OsvClient, httpx.AsyncClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def recording_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(recording_handler))
    return OsvClient(_settings(), http_client=http), http, seen


@pytest.mark.asyncio
async def test_client_sends_valid_batch_and_hydrates_full_records() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "TEST-OSV-2", "modified": "2024-01-02T00:00:00Z"}]}, {}]},
            )
        if request.url.path == "/v1/vulns/TEST-OSV-2":
            return httpx.Response(200, json=_synthetic_vuln("TEST-OSV-2", "vuln-lib"))
        return httpx.Response(404)

    osv, http, seen = _mock_osv_client(handler)
    queries = [_query("vuln-lib", "1.0.0"), _query("clean-lib", "2.0.0")]
    try:
        results, failures = await osv.query_batch(queries)
    finally:
        await http.aclose()

    batch_req = seen[0]
    assert batch_req.method == "POST"
    assert str(batch_req.url) == "http://osv.test/v1/querybatch"
    assert json.loads(batch_req.content) == {
        "queries": [
            {"package": {"name": "vuln-lib", "ecosystem": "npm"}, "version": "1.0.0"},
            {"package": {"name": "clean-lib", "ecosystem": "npm"}, "version": "2.0.0"},
        ]
    }
    assert [(r.method, r.url.path) for r in seen[1:]] == [("GET", "/v1/vulns/TEST-OSV-2")]
    assert failures == []
    assert results[queries[1]] == []
    hydrated = results[queries[0]][0]
    assert hydrated.id == "TEST-OSV-2"
    assert hydrated.summary == "Synthetic advisory for vuln-lib"
    assert "9.9.9" in hydrated.fixed_versions


@pytest.mark.asyncio
async def test_client_hydration_failure_marks_query_failed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "TEST-OSV-404"}]}]})
        return httpx.Response(404)

    osv, http, _ = _mock_osv_client(handler)
    q = _query("vuln-lib", "1.0.0")
    try:
        results, failures = await osv.query_batch([q])
    finally:
        await http.aclose()

    assert results == {}
    assert failures[0][0] == q
    assert "TEST-OSV-404" in failures[0][1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("batch_body", "expected"),
    [
        ({"results": []}, "no result for this query"),
        ({"results": [{"vulns": [{"id": "TEST-OSV-3"}], "next_page_token": "abc"}]}, "paginated"),
    ],
)
async def test_client_incomplete_batch_results_are_failures(batch_body: dict[str, Any], expected: str) -> None:
    osv, http, seen = _mock_osv_client(lambda request: httpx.Response(200, json=batch_body))
    q = _query("vuln-lib", "1.0.0")
    try:
        results, failures = await osv.query_batch([q])
    finally:
        await http.aclose()

    assert results == {}
    assert len(failures) == 1 and expected in failures[0][1]
    assert len(seen) == 1


# ---------------------------------------------------------------------
# API counters match the service result
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_advisory_import_endpoint_exposes_per_package_outcomes(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
    mock_advisory_repo: InMemoryAdvisoryRepository,
) -> None:
    from unittest.mock import patch

    authenticate_client(client)
    project = mock_project_repo.create_project(name="Regression Scan", ecosystem="npm", description="")

    empty = await client.post(f"/api/projects/{project.id}/advisories/import")
    assert empty.status_code == 200
    assert empty.json()["status"] == "skipped"

    mock_advisory_repo.set_project_packages(project.id, [_pkg("vuln-lib", "1.0.0"), _pkg("clean-lib", "2.0.0")])
    vuln = parse_osv_vulnerability(_synthetic_vuln("TEST-OSV-4", "vuln-lib"), retrieved_at=1700000000)

    async def fake_batch(queries, **_):
        return {q: ([vuln] if q.package.name == "vuln-lib" else []) for q in queries}, []

    with patch.object(OsvClient, "query_batch", side_effect=fake_batch):
        res = await client.post(f"/api/projects/{project.id}/advisories/import", params={"force_refresh": "true"})

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["eligible_package_versions"] == 2
    assert data["packages_with_advisories"] == 1
    assert data["packages_with_no_advisories"] == 1
    assert {r["name"]: r["outcome"] for r in data["package_results"]} == {
        "vuln-lib": "advisories_found",
        "clean-lib": "no_advisories",
    }


# ---------------------------------------------------------------------
# FalkorDB persistence (skipped when the graph is unreachable)
# ---------------------------------------------------------------------

@pytest.fixture
def falkor_db():
    from vulnify.graph.client import get_graph_client

    try:
        client = get_graph_client()
        client.get_graph().query("RETURN 1")
        return client
    except Exception as exc:
        pytest.skip(f"FalkorDB is not reachable: {exc}")


@pytest.mark.asyncio
async def test_falkor_lockfile_import_then_scan_links_correct_package(falkor_db) -> None:
    from vulnify.graph.advisory_repository import FalkorAdvisoryRepository
    from vulnify.graph.dependency_repository import FalkorDependencyRepository
    from vulnify.graph.project_repository import FalkorProjectRepository

    graph = falkor_db.get_graph()
    suffix = uuid.uuid4().hex[:8]
    root_name, trans_name = f"root-lib-{suffix}", f"trans-lib-{suffix}"
    vuln_id = f"TEST-OSV-{suffix}"
    project = FalkorProjectRepository(client=falkor_db).create_project(
        name=f"OSV Regression {suffix}", ecosystem="npm", description="US-103 regression"
    )
    service_name = f"billing-svc-{suffix}"
    service_id = f"{project.id}:{service_name}"

    try:
        lockfile = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {root_name: "^1.0.0"}},
                f"node_modules/{root_name}": {"version": "1.0.0", "dependencies": {trans_name: "^2.1.0"}},
                f"node_modules/{trans_name}": {"version": "2.1.0"},
            },
        }
        raw = json.dumps(lockfile).encode()
        FalkorDependencyRepository(client=falkor_db).import_dependencies(
            project_id=project.id,
            service_name=service_name,
            filename="package-lock.json",
            sha256_hash=hashlib.sha256(raw).hexdigest(),
            parsed_graph=parse_npm_lockfile(raw, filename="package-lock.json"),
        )

        advisory_repo = FalkorAdvisoryRepository(client=falkor_db)
        discovered = advisory_repo.get_project_package_versions(project.id)
        assert sorted((p.name, p.version, p.ecosystem) for p in discovered) == [
            (root_name, "1.0.0", "npm"),
            (trans_name, "2.1.0", "npm"),
        ]

        vuln = parse_osv_vulnerability(_synthetic_vuln(vuln_id, trans_name), retrieved_at=1700000000)
        stub = StubOsvClient(results={_query(root_name, "1.0.0"): [], _query(trans_name, "2.1.0"): [vuln]})
        service = OsvService(settings=_settings(), advisory_repo=advisory_repo, client=stub, cache=OsvCache(300))

        summary = await service.import_project_advisories(project.id)

        assert summary.status == "completed"
        assert summary.total_package_versions == 2
        assert summary.eligible_package_versions == 2
        assert summary.packages_with_advisories == 1
        assert summary.packages_with_no_advisories == 1
        assert summary.advisories_found == 1
        assert summary.relationships_created == 1

        linked = graph.query(
            "MATCH (pv:PackageVersion)-[:HAS_ADVISORY]->(v:Vulnerability {id: $vid}) RETURN pv.id",
            {"vid": vuln_id},
        ).result_set
        assert [row[0] for row in linked] == [f"npm:{trans_name}@2.1.0"]
        affects = graph.query(
            "MATCH (v:Vulnerability {id: $vid})-[:AFFECTS]->(pv:PackageVersion) RETURN pv.id",
            {"vid": vuln_id},
        ).result_set
        assert [row[0] for row in affects] == [f"npm:{trans_name}@2.1.0"]

        rows = advisory_repo.get_project_advisories(project.id)
        assert [(r["id"], r["package_name"], r["package_version"]) for r in rows] == [(vuln_id, trans_name, "2.1.0")]

        rerun = await service.import_project_advisories(project.id, force_refresh=True)
        assert rerun.relationships_created == 0
        assert rerun.relationships_reused == 1
    finally:
        for query, params in (
            ("MATCH (v:Vulnerability {id: $vid}) DETACH DELETE v", {"vid": vuln_id}),
            ("MATCH (s:Service {id: $sid})-[:IMPORTED_FROM]->(ie:ImportEvent) DETACH DELETE ie", {"sid": service_id}),
            ("MATCH (s:Service {id: $sid}) DETACH DELETE s", {"sid": service_id}),
            ("MATCH (pv:PackageVersion) WHERE pv.id CONTAINS $suffix DETACH DELETE pv", {"suffix": suffix}),
            ("MATCH (p:Project {id: $pid}) DETACH DELETE p", {"pid": project.id}),
        ):
            try:
                graph.query(query, params)
            except Exception:
                pass
