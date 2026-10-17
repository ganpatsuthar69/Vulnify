"""Performance test verifying US-102 acceptance criterion: 5,000 packages imported in under 30 seconds."""

import hashlib
import json
import time
import uuid
import pytest

from vulnify.graph.client import get_graph_client
from vulnify.graph.dependency_repository import FalkorDependencyRepository
from vulnify.graph.project_repository import FalkorProjectRepository
from vulnify.parsers.npm import parse_npm_lockfile


@pytest.fixture
def falkor_client():
    try:
        client = get_graph_client()
        graph = client.get_graph()
        graph.query("RETURN 1")
        return client
    except Exception as exc:
        pytest.skip(f"FalkorDB is not reachable: {exc}")


def generate_5000_package_lockfile(test_run_id: str) -> dict:
    """Generate a realistic synthetic npm lockfile with 5,000 packages and dependency relationships."""
    packages: dict = {}
    direct_deps: dict[str, str] = {}

    # 100 direct dependencies
    for d in range(100):
        pkg_name = f"@synth-{test_run_id}/direct-service-pkg-{d:03d}"
        direct_deps[pkg_name] = "^1.0.0"

    packages[""] = {
        "name": f"synthetic-perf-app-{test_run_id}",
        "version": "1.0.0",
        "dependencies": direct_deps,
    }

    # Total 5,000 packages: 100 direct, 4,900 transitive packages
    # Each package depends on 1 or 2 downstream packages to create realistic DAG depth
    total_packages = 5000
    for i in range(total_packages):
        pkg_name = (
            f"@synth-{test_run_id}/direct-service-pkg-{i:03d}"
            if i < 100
            else f"@synth-{test_run_id}/transitive-pkg-{i:04d}"
        )
        path_key = f"node_modules/{pkg_name}"
        version = f"{(i % 10) + 1}.{(i % 20)}.{(i % 5)}"

        deps: dict[str, str] = {}
        # Connect to downstream packages within the 5,000 pool
        if i + 1 < total_packages:
            downstream_1 = (
                f"@synth-{test_run_id}/direct-service-pkg-{(i + 1):03d}"
                if (i + 1) < 100
                else f"@synth-{test_run_id}/transitive-pkg-{(i + 1):04d}"
            )
            deps[downstream_1] = "^1.0.0"

        if (i + 2) < total_packages and i % 3 == 0:
            downstream_2 = (
                f"@synth-{test_run_id}/direct-service-pkg-{(i + 2):03d}"
                if (i + 2) < 100
                else f"@synth-{test_run_id}/transitive-pkg-{(i + 2):04d}"
            )
            deps[downstream_2] = "^1.0.0"

        packages[path_key] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{pkg_name}/-/{version}.tgz",
            "dependencies": deps,
        }

    return {
        "name": f"synthetic-perf-app-{test_run_id}",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": packages,
    }


def test_import_5000_packages_under_30_seconds(falkor_client) -> None:
    graph = falkor_client.get_graph()
    proj_repo = FalkorProjectRepository(client=falkor_client)
    dep_repo = FalkorDependencyRepository(client=falkor_client)

    test_run_id = str(uuid.uuid4())[:8]
    proj_name = f"Perf Project {test_run_id}"
    project = proj_repo.create_project(name=proj_name, ecosystem="npm", description="Scale performance test")
    service_name = f"perf-service-{test_run_id}"
    service_id = f"{project.id}:{service_name}"

    try:
        # Generate 5,000 package lockfile
        lockfile_data = generate_5000_package_lockfile(test_run_id)
        lockfile_bytes = json.dumps(lockfile_data).encode("utf-8")
        file_hash = hashlib.sha256(lockfile_bytes).hexdigest()
        filename = "package-lock.json"

        # Measure end-to-end parsing + graph persistence time
        start_time = time.perf_counter()

        # Step 1: Parse
        parse_start = time.perf_counter()
        parsed_graph = parse_npm_lockfile(lockfile_bytes, filename=filename)
        parse_duration = time.perf_counter() - parse_start

        assert len(parsed_graph.packages) == 5000
        assert len(parsed_graph.direct_dependency_ids) == 100

        # Step 2: Persist into FalkorDB
        db_start = time.perf_counter()
        summary = dep_repo.import_dependencies(
            project_id=project.id,
            service_name=service_name,
            filename=filename,
            sha256_hash=file_hash,
            parsed_graph=parsed_graph,
        )
        db_duration = time.perf_counter() - db_start

        total_duration = time.perf_counter() - start_time

        print(f"\n[PERFORMANCE RESULTS]")
        print(f"Total Packages: {summary.packages_parsed}")
        print(f"Packages Created: {summary.packages_created}")
        print(f"Edges Created: {summary.edges_created}")
        print(f"Parse Duration: {parse_duration:.3f}s")
        print(f"Graph DB Persistence Duration: {db_duration:.3f}s")
        print(f"Total End-to-End Duration: {total_duration:.3f}s (Acceptance Target: < 30.0s)")

        # Acceptance Criterion: under 30 seconds
        assert total_duration < 30.0, f"Import took {total_duration:.2f}s, exceeding 30s threshold"
        assert summary.status == "completed"
        assert summary.packages_created == 5000

    finally:
        # Cleanup performance nodes
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
                {"suffix": test_run_id},
            )
            graph.query("MATCH (p:Project {id: $pid}) DETACH DELETE p", {"pid": project.id})
        except Exception:
            pass
