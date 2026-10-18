"""Tests for the bounded, project-scoped graph explorer API and FalkorDB repository."""

import hashlib
import json
import uuid
from typing import Any

from fastapi import FastAPI
from httpx import AsyncClient
import pytest

from vulnify.graph.dependency_repository import FalkorDependencyRepository
from vulnify.graph.explorer_models import ProjectGraphResponse
from vulnify.graph.explorer_repository import (
    ExplorerNodeNotFound,
    FalkorExplorerRepository,
    get_explorer_repository,
)
from vulnify.graph.project_repository import (
    FalkorProjectRepository,
    InMemoryProjectRepository,
    ProjectRecord,
)
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.parsers.npm import parse_npm_lockfile
from tests.conftest import ADMIN_USER, authenticate_client


@pytest.fixture
def falkor_db():
    from vulnify.graph.client import get_graph_client
    try:
        client = get_graph_client()
        client.get_graph().query("RETURN 1")
        return client
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"FalkorDB is not reachable: {exc}")


def _lockfile(root_name: str, root_version: str, chain: list[tuple[str, str]]) -> bytes:
    packages: dict[str, Any] = {
        "": {"dependencies": {root_name: root_version}},
        f"node_modules/{root_name}": {
            "version": root_version,
            "dependencies": {chain[0][0]: chain[0][1]} if chain else {},
        },
    }
    for i, (name, version) in enumerate(chain):
        nxt = chain[i + 1] if i + 1 < len(chain) else None
        packages[f"node_modules/{name}"] = {
            "version": version,
            "dependencies": {nxt[0]: nxt[1]} if nxt else {},
        }
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages}).encode()


@pytest.fixture
def scoped_projects(falkor_db):
    """Two projects sharing middle package Y; each exclusive tail must not leak."""
    graph = falkor_db.get_graph()
    proj_repo = FalkorProjectRepository(client=falkor_db)
    dep_repo = FalkorDependencyRepository(client=falkor_db)
    suffix = uuid.uuid4().hex[:8]
    raw = {
        name: f"npm:{name}-{suffix}@{version}"
        for name, version in (("x", "1.0.0"), ("y", "2.0.0"), ("z", "3.0.0"))
    }
    nodes = {name: f"package:{node_id}" for name, node_id in raw.items()}
    projects: list[Any] = []
    try:
        for index, (head_name, tail_name) in enumerate((("x", "y"), ("y", "z"))):
            project = proj_repo.create_project(
                name=f"Explorer {index} {suffix}", ecosystem="npm", description="scoped graph test",
            )
            projects.append(project)
            head, tail = raw[head_name], raw[tail_name]
            parsed = parse_npm_lockfile(
                _lockfile(
                    head.split(":")[1].rsplit("@", 1)[0], head.split("@")[-1],
                    [(tail.split(":")[1].rsplit("@", 1)[0], tail.split("@")[-1])],
                ),
                filename="package-lock.json",
            )
            dep_repo.import_dependencies(
                project_id=project.id, service_name=f"svc-{index}-{suffix}",
                filename="package-lock.json", sha256_hash="t" * 64, parsed_graph=parsed,
            )
        yield graph, projects, raw, nodes, suffix
    finally:
        for project in projects:
            graph.query(
                "MATCH (s:Service) WHERE s.id STARTS WITH $pid DETACH DELETE s", {"pid": project.id},
            )
            graph.query(
                "MATCH (ie:ImportEvent) WHERE ie.project_id = $pid DETACH DELETE ie", {"pid": project.id},
            )
            graph.query("MATCH (p:Project {id: $pid}) DETACH DELETE p", {"pid": project.id})
        graph.query(
            "MATCH (pv:PackageVersion) WHERE pv.id IN $ids DETACH DELETE pv",
            {"ids": list(raw.values())},
        )


def test_graph_is_project_scoped_and_depth_classified(scoped_projects) -> None:
    _graph, (p1, p2), _raw, n, suffix = scoped_projects
    repo = FalkorExplorerRepository()
    res1 = repo.get_project_graph(p1.id)
    packages1 = {node.id: node for node in res1.nodes if node.node_type == "package"}
    assert packages1[n["x"]].classification == "direct" and packages1[n["x"]].depth == 2
    assert packages1[n["y"]].classification == "transitive" and packages1[n["y"]].depth == 3
    assert n["z"] not in packages1, "P2-only transitive tail leaked into P1"
    assert f"service:{p1.id}:svc-0-{suffix}" in {node.id for node in res1.nodes}

    res2 = repo.get_project_graph(p2.id)
    packages2 = {node.id: node for node in res2.nodes if node.node_type == "package"}
    assert packages2[n["y"]].classification == "direct"
    assert packages2[n["z"]].classification == "transitive"
    assert n["x"] not in packages2, "P1-only root leaked into P2"
    assert res2.total_packages == 2


def test_advisory_and_finding_ids_attached(scoped_projects) -> None:
    graph, (p1, _p2), raw, n, suffix = scoped_projects
    adv = f"GHSA-test-{uuid.uuid4().hex[:8]}"
    ignored = f"GHSA-ignored-{uuid.uuid4().hex[:8]}"
    graph.query(
        "CREATE (v:Vulnerability {id: $id, severity: 'High', summary: 'test'})"
        "-[:AFFECTS {status: 'affected', reason: 'range'}]->(:PackageVersion {id: $pv})",
        {"id": adv, "pv": raw["y"]},
    )
    graph.query(
        "CREATE (v:Vulnerability {id: $id, severity: 'Low', summary: 'triaged'})"
        "-[:AFFECTS {status: 'affected', triage_status: 'not_affected'}]->(:PackageVersion {id: $pv})",
        {"id": ignored, "pv": raw["y"]},
    )
    try:
        res = FalkorExplorerRepository().get_project_graph(p1.id, q=adv)
        advisory = next(node for node in res.nodes if node.id == f"advisory:{adv}")
        assert advisory.severity == "High"
        edge = next(edge for edge in res.edges if edge.source == advisory.id)
        assert edge.relationship_type == "AFFECTS" and edge.target == n["y"]
        service_id = f"{p1.id}:svc-0-{suffix}"
        expected = "find-" + hashlib.sha256(
            f"{p1.id}:{service_id}:{adv}:{raw['y']}".encode()
        ).hexdigest()[:16]
        assert edge.properties["finding_ids"] == [expected]
        assert not any(node.id == f"advisory:{ignored}" for node in res.nodes)
        pkg = next(node for node in res.nodes if node.id == n["y"])
        assert pkg.advisory_count == 1
    finally:
        graph.query(
            "MATCH (v:Vulnerability) WHERE v.id IN $ids DETACH DELETE v", {"ids": [adv, ignored]},
        )


def test_legacy_unscoped_edges_warn_and_are_excluded(scoped_projects) -> None:
    graph, (p1, _p2), raw, _n, _suffix = scoped_projects
    orphan = f"npm:orphan-{uuid.uuid4().hex[:8]}@1.0.0"
    graph.query(
        "CREATE (:PackageVersion {id: $orphan, name: 'orphan', version: '1.0.0', ecosystem: 'npm'})",
        {"orphan": orphan},
    )
    graph.query(
        "MATCH (a:PackageVersion {id: $a}), (b:PackageVersion {id: $orphan})"
        "MERGE (a)-[:DEPENDS_ON {direct: false, origin: 'manifest'}]->(b)",
        {"a": raw["y"], "orphan": orphan},
    )
    try:
        res = FalkorExplorerRepository().get_project_graph(p1.id)
        assert orphan not in {node.id for node in res.nodes}
        assert not res.counts_complete
        assert any("Legacy dependency edges without service provenance" in w for w in res.warnings)
    finally:
        graph.query("MATCH (pv:PackageVersion {id: $id}) DETACH DELETE pv", {"id": orphan})


def test_cycles_and_pagination_and_bounds(falkor_db) -> None:
    graph = falkor_db.get_graph()
    suffix = uuid.uuid4().hex[:8]
    project = FalkorProjectRepository(client=falkor_db).create_project(
        name=f"Explorer cycle {suffix}", ecosystem="npm", description="cycle",
    )
    a, b = f"npm:ca-{suffix}@1.0.0", f"npm:cb-{suffix}@1.0.0"
    service_id = f"{project.id}:svc-cycle"
    try:
        graph.query(
            "MATCH (p:Project {id: $pid}) CREATE (p)-[:HAS_SERVICE]->(s:Service {id: $sid, name: 'svc'})",
            {"pid": project.id, "sid": service_id},
        )
        graph.query(
            "CREATE (:PackageVersion {id: $a, name: 'ca', version: '1.0.0', ecosystem: 'npm'})",
            {"a": a},
        )
        graph.query(
            "CREATE (:PackageVersion {id: $b, name: 'cb', version: '1.0.0', ecosystem: 'npm'})",
            {"b": b},
        )
        graph.query(
            "MATCH (s:Service {id: $sid}), (a:PackageVersion {id: $a}) MERGE (s)-[:DEPENDS_ON {direct: true}]->(a)",
            {"sid": service_id, "a": a},
        )
        graph.query(
            "MATCH (a:PackageVersion {id: $a}), (b:PackageVersion {id: $b}) "
            "MERGE (a)-[r1:DEPENDS_ON]->(b) SET r1.service_ids = [$sid] "
            "MERGE (b)-[r2:DEPENDS_ON]->(a) SET r2.service_ids = [$sid]",
            {"a": a, "b": b, "sid": service_id},
        )
        repo = FalkorExplorerRepository()
        res = repo.get_project_graph(project.id)
        assert {f"package:{a}", f"package:{b}"} == {
            node.id for node in res.nodes if node.node_type == "package"
        }

        page1 = repo.get_project_graph(project.id, limit=1)
        page2 = repo.get_project_graph(project.id, limit=1, offset=page1.next_offset)
        assert page1.has_more and page2.has_more is False
        assert {node.id for node in page1.nodes if node.node_type == "package"} != {
            node.id for node in page2.nodes if node.node_type == "package"
        }

        with pytest.raises(ValueError):
            repo.get_project_graph(project.id, limit=101)
        with pytest.raises(ValueError):
            repo.get_project_graph(project.id, offset=-1)
        with pytest.raises(ExplorerNodeNotFound):
            repo.get_project_graph(project.id, node_id=f"package:npm:missing-{suffix}@9.9.9")
    finally:
        graph.query("MATCH (s:Service {id: $sid}) DETACH DELETE s", {"sid": service_id})
        graph.query("MATCH (p:Project {id: $pid}) DETACH DELETE p", {"pid": project.id})
        graph.query("MATCH (pv:PackageVersion) WHERE pv.id IN $ids DETACH DELETE pv", {"ids": [a, b]})


class _StubExplorer:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}

    def get_project_graph(self, project_id: str, **kwargs: Any) -> ProjectGraphResponse:
        self.kwargs = {"project_id": project_id, **kwargs}
        return ProjectGraphResponse(
            project_id=project_id, root_id=f"project:{project_id}",
            nodes=[{"id": f"project:{project_id}", "node_type": 'project', "label": "p"}],
            edges=[], total_packages=0, total_advisories=0, counts_complete=True,
            has_more=False, next_offset=None, warnings=["stub warning"],
        )


def _seed_mock_project(
    mock_user_repo: InMemoryUserRepository, mock_project_repo: InMemoryProjectRepository,
) -> None:
    mock_user_repo.create_user(email=ADMIN_USER["email"], name=ADMIN_USER["name"], password_hash="h", role="admin")
    user = mock_user_repo.get_by_email(ADMIN_USER["email"])
    if user:
        user.id = ADMIN_USER["id"]
        mock_user_repo._users_by_id[ADMIN_USER["id"]] = user
    project = ProjectRecord(
        id="proj-graph-1", name="Graph Explorer Test", normalized_name="graph explorer test",
        ecosystem="npm", description=None, created_at=1700000000,
    )
    mock_project_repo._projects_by_id[project.id] = project
    mock_project_repo._projects_by_norm[project.normalized_name] = project


async def test_graph_api_auth_and_query_pass_through(
    app: FastAPI, client: AsyncClient,
    mock_user_repo: InMemoryUserRepository, mock_project_repo: InMemoryProjectRepository,
) -> None:
    unauth = await client.get("/api/projects/proj-graph-1/graph")
    assert unauth.status_code == 401

    _seed_mock_project(mock_user_repo, mock_project_repo)
    stub = _StubExplorer()
    app.dependency_overrides[get_explorer_repository] = lambda: stub
    authenticate_client(client)
    res = await client.get(
        "/api/projects/proj-graph-1/graph",
        params={"node_id": "package:npm:lodash@4.17.21", "q": "lodash", "offset": 2, "limit": 7},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["root_id"] == "project:proj-graph-1" and body["warnings"] == ["stub warning"]
    assert stub.kwargs == {
        "project_id": "proj-graph-1", "node_id": "package:npm:lodash@4.17.21",
        "q": "lodash", "offset": 2, "limit": 7,
    }

    bad = await client.get("/api/projects/proj-graph-1/graph", params={"node_id": "bogus"})
    assert bad.status_code == 422
    big = await client.get("/api/projects/proj-graph-1/graph", params={"limit": 500})
    assert big.status_code == 422


async def test_graph_api_404_and_503(
    app: FastAPI, client: AsyncClient,
    mock_user_repo: InMemoryUserRepository, mock_project_repo: InMemoryProjectRepository,
) -> None:
    _seed_mock_project(mock_user_repo, mock_project_repo)
    authenticate_client(client)

    class _NotFound:
        def get_project_graph(self, project_id: str, **kwargs: Any):
            raise ExplorerNodeNotFound("missing")

    app.dependency_overrides[get_explorer_repository] = lambda: _NotFound()
    assert (await client.get("/api/projects/proj-graph-1/graph")).status_code == 404

    class _Down:
        def get_project_graph(self, project_id: str, **kwargs: Any):
            raise ConnectionError("db down")

    app.dependency_overrides[get_explorer_repository] = lambda: _Down()
    assert (await client.get("/api/projects/proj-graph-1/graph")).status_code == 503
