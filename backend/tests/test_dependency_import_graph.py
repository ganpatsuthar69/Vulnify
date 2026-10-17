"""Integration tests against FalkorDB graph database verifying US-102 dependency persistence and idempotency."""

import hashlib
import json
import uuid
import pytest

from vulnify.graph.client import get_graph_client
from vulnify.graph.dependency_repository import FalkorDependencyRepository
from vulnify.graph.project_repository import FalkorProjectRepository
from vulnify.parsers.npm import parse_npm_lockfile


@pytest.fixture
def falkor_db():
    try:
        client = get_graph_client()
        graph = client.get_graph()
        # Verify connectivity
        graph.query("RETURN 1")
        return client
    except Exception as exc:
        pytest.skip(f"FalkorDB is not reachable: {exc}")


def test_falkor_graph_dependency_import_and_idempotency(falkor_db) -> None:
    graph = falkor_db.get_graph()
    proj_repo = FalkorProjectRepository(client=falkor_db)
    dep_repo = FalkorDependencyRepository(client=falkor_db)

    # 1. Create a isolated test project in FalkorDB
    unique_suffix = str(uuid.uuid4())[:8]
    proj_name = f"Test Integration Proj {unique_suffix}"
    project = proj_repo.create_project(name=proj_name, ecosystem="npm", description="Integration test project")
    service_name = f"billing-svc-{unique_suffix}"
    service_id = f"{project.id}:{service_name}"

    try:
        # 2. Build test lockfile with direct & transitive dependencies
        lockfile_data = {
            "name": "billing-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {
                        f"root-lib-{unique_suffix}": "1.0.0",
                    },
                },
                f"node_modules/root-lib-{unique_suffix}": {
                    "version": "1.0.0",
                    "dependencies": {
                        f"trans-lib-{unique_suffix}": "2.1.0",
                    },
                },
                f"node_modules/trans-lib-{unique_suffix}": {
                    "version": "2.1.0",
                },
            },
        }

        lockfile_bytes = json.dumps(lockfile_data).encode("utf-8")
        file_hash = hashlib.sha256(lockfile_bytes).hexdigest()
        filename = "package-lock.json"
        parsed = parse_npm_lockfile(lockfile_bytes, filename=filename)

        # 3. First Import: Persist graph into FalkorDB
        summary1 = dep_repo.import_dependencies(
            project_id=project.id,
            service_name=service_name,
            filename=filename,
            sha256_hash=file_hash,
            parsed_graph=parsed,
        )

        assert summary1.status == "completed"
        assert summary1.packages_parsed == 2
        assert summary1.packages_created == 2
        assert summary1.packages_reused == 0
        assert summary1.edges_created == 2  # 1 service->root, 1 root->trans
        assert summary1.edges_reused == 0

        # Verify Service node exists and is connected to Project
        svc_res = graph.query(
            "MATCH (p:Project {id: $pid})-[:HAS_SERVICE]->(s:Service {id: $sid}) RETURN s.name",
            {"pid": project.id, "sid": service_id},
        )
        assert len(svc_res.result_set) == 1
        assert svc_res.result_set[0][0] == service_name

        # Verify direct dependency from Service to root-lib
        direct_res = graph.query(
            "MATCH (s:Service {id: $sid})-[r:DEPENDS_ON]->(pv:PackageVersion) "
            "RETURN pv.id, r.direct, r.origin",
            {"sid": service_id},
        )
        assert len(direct_res.result_set) == 1
        assert direct_res.result_set[0][0] == f"npm:root-lib-{unique_suffix}@1.0.0"
        assert direct_res.result_set[0][1] is True
        assert direct_res.result_set[0][2] == "manifest"

        # Verify transitive dependency edge from root-lib to trans-lib
        trans_res = graph.query(
            "MATCH (src:PackageVersion {id: $src_id})-[r:DEPENDS_ON]->(dst:PackageVersion {id: $dst_id}) "
            "RETURN r.direct, r.origin",
            {
                "src_id": f"npm:root-lib-{unique_suffix}@1.0.0",
                "dst_id": f"npm:trans-lib-{unique_suffix}@2.1.0",
            },
        )
        assert len(trans_res.result_set) == 1
        assert trans_res.result_set[0][0] is False
        assert trans_res.result_set[0][1] == "manifest"

        # Verify ImportEvent provenance record
        import_res = graph.query(
            "MATCH (s:Service {id: $sid})-[:IMPORTED_FROM]->(ie:ImportEvent {sha256_hash: $hash}) "
            "RETURN ie.filename, ie.packages_count, ie.edges_count",
            {"sid": service_id, "hash": file_hash},
        )
        assert len(import_res.result_set) == 1
        assert import_res.result_set[0][0] == filename
        assert import_res.result_set[0][1] == 2
        assert import_res.result_set[0][2] == 2

        # 4. Count total nodes and edges before second import
        pv_count_before = graph.query(
            "MATCH (pv:PackageVersion) WHERE pv.id STARTS WITH $prefix RETURN count(pv)",
            {"prefix": f"npm:root-lib-{unique_suffix}"},
        ).result_set[0][0]
        assert pv_count_before == 1

        # 5. Second Import (Idempotency): Reimport exact same file
        summary2 = dep_repo.import_dependencies(
            project_id=project.id,
            service_name=service_name,
            filename=filename,
            sha256_hash=file_hash,
            parsed_graph=parsed,
        )

        assert summary2.status == "completed"
        assert summary2.packages_parsed == 2
        assert summary2.packages_created == 0
        assert summary2.packages_reused == 2
        assert summary2.edges_created == 0
        assert summary2.edges_reused == 2

        # Verify NO duplicate PackageVersion nodes were created
        pv_count_after = graph.query(
            "MATCH (pv:PackageVersion) WHERE pv.id STARTS WITH $prefix RETURN count(pv)",
            {"prefix": f"npm:root-lib-{unique_suffix}"},
        ).result_set[0][0]
        assert pv_count_after == 1

        # Verify NO duplicate edges were created from Service
        svc_edges_after = graph.query(
            "MATCH (s:Service {id: $sid})-[r:DEPENDS_ON]->(pv:PackageVersion) RETURN count(r)",
            {"sid": service_id},
        ).result_set[0][0]
        assert svc_edges_after == 1

    finally:
        # Cleanup test-isolated nodes without touching other data
        try:
            graph.query(
                "MATCH (s:Service {id: $sid})-[r:IMPORTED_FROM]->(ie:ImportEvent) DETACH DELETE ie",
                {"sid": service_id},
            )
            graph.query(
                "MATCH (p:Project {id: $pid})-[r:HAS_SERVICE]->(s:Service {id: $sid}) DETACH DELETE s",
                {"pid": project.id, "sid": service_id},
            )
            graph.query(
                "MATCH (pv:PackageVersion) WHERE pv.id CONTAINS $suffix DETACH DELETE pv",
                {"suffix": unique_suffix},
            )
            graph.query("MATCH (p:Project {id: $pid}) DETACH DELETE p", {"pid": project.id})
        except Exception:
            pass
