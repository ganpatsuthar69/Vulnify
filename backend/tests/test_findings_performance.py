"""Performance test verifying US-201 acceptance criterion: 500 findings load in under 2 seconds."""

import time
import uuid
import pytest

from vulnify.graph.client import get_graph_client
from vulnify.graph.vulnerability_repository import FalkorVulnerabilityRepository


@pytest.fixture
def falkor_client():
    try:
        client = get_graph_client()
        graph = client.get_graph()
        graph.query("RETURN 1")
        return client
    except Exception as exc:
        pytest.skip(f"FalkorDB is not reachable: {exc}")


def test_500_findings_load_in_under_2_seconds(falkor_client):
    """US-201 Acceptance Criterion: 500 findings load in under 2 seconds."""
    graph = falkor_client.get_graph()
    run_id = uuid.uuid4().hex[:8]
    project_id = f"proj-perf-{run_id}"
    service_id = f"{project_id}:api"
    service_name = f"api-{run_id}"

    repo = FalkorVulnerabilityRepository(client=falkor_client)

    try:
        # 1. Create Project and Service
        graph.query(
            """
            CREATE (p:Project {
                id: $pid,
                name: $pname,
                normalized_name: $pname,
                ecosystem: 'npm',
                created_at: 1700000000
            })
            CREATE (s:Service {
                id: $sid,
                name: $sname,
                ecosystem: 'npm',
                created_at: 1700000000
            })
            CREATE (p)-[:HAS_SERVICE]->(s)
            """,
            {"pid": project_id, "pname": f"Perf Project {run_id}", "sid": service_id, "sname": service_name},
        )

        # 2. Batch-create 500 vulnerabilities, packages, dependencies, and AFFECTS relationships
        batch_size = 100
        total_findings = 500

        for b in range(0, total_findings, batch_size):
            batch_items = []
            for i in range(b, b + batch_size):
                pkg_name = f"pkg-{run_id}-{i:04d}"
                pkg_ver = f"npm:{pkg_name}@1.0.0"
                adv_id = f"OSV-PERF-{run_id}-{i:04d}"
                vuln_id = f"vuln-{adv_id}"
                # Alternate direct (depth 1) and transitive (depth 2) dependencies
                is_transitive = (i % 2 == 1)
                intermediate_pkg = f"pkg-{run_id}-direct-{i // 2:04d}" if is_transitive else None

                batch_items.append({
                    "idx": i,
                    "pkg_name": pkg_name,
                    "pkg_ver": pkg_ver,
                    "adv_id": adv_id,
                    "vuln_id": vuln_id,
                    "summary": f"Performance vulnerability {i}",
                    "is_transitive": is_transitive,
                    "mid_pkg_ver": f"npm:{intermediate_pkg}@1.0.0" if intermediate_pkg else None,
                    "mid_pkg_name": intermediate_pkg,
                })

            # Create direct and transitive graph structures
            for item in batch_items:
                if not item["is_transitive"]:
                    # Service -[:DEPENDS_ON]-> PackageVersion <-[:AFFECTS]- Vulnerability
                    graph.query(
                        """
                        MATCH (s:Service {id: $sid})
                        CREATE (pv:PackageVersion {
                            id: $pkg_ver,
                            name: $pkg_name,
                            version: '1.0.0',
                            ecosystem: 'npm'
                        })
                        CREATE (v:Vulnerability {
                            id: $vuln_id,
                            advisory_id: $adv_id,
                            summary: $summary,
                            severity: 'HIGH',
                            source_url: 'https://osv.dev',
                            retrieved_at: 1700000000
                        })
                        CREATE (s)-[:DEPENDS_ON {origin: 'manifest'}]->(pv)
                        CREATE (v)-[:AFFECTS {
                            status: 'affected',
                            package_name: $pkg_name,
                            ecosystem: 'npm',
                            reason: 'Matched version 1.0.0',
                            reason_code: 'WITHIN_AFFECTED_RANGE',
                            fixed_version: '2.0.0'
                        }]->(pv)
                        """,
                        {
                            "sid": service_id,
                            "pkg_ver": item["pkg_ver"],
                            "pkg_name": item["pkg_name"],
                            "vuln_id": item["adv_id"],
                            "adv_id": item["adv_id"],
                            "summary": item["summary"],
                        },
                    )
                else:
                    # Service -[:DEPENDS_ON]-> MidPV -[:DEPENDS_ON]-> PV <-[:AFFECTS]- Vulnerability
                    graph.query(
                        """
                        MATCH (s:Service {id: $sid})
                        MERGE (mid:PackageVersion {id: $mid_pkg_ver})
                        ON CREATE SET mid.name = $mid_pkg_name, mid.version = '1.0.0', mid.ecosystem = 'npm'
                        MERGE (s)-[:DEPENDS_ON {origin: 'manifest'}]->(mid)
                        CREATE (pv:PackageVersion {
                            id: $pkg_ver,
                            name: $pkg_name,
                            version: '1.0.0',
                            ecosystem: 'npm'
                        })
                        CREATE (v:Vulnerability {
                            id: $adv_id,
                            advisory_id: $adv_id,
                            summary: $summary,
                            severity: 'HIGH',
                            source_url: 'https://osv.dev',
                            retrieved_at: 1700000000
                        })
                        CREATE (mid)-[:DEPENDS_ON {origin: 'lockfile'}]->(pv)
                        CREATE (v)-[:AFFECTS {
                            status: 'affected',
                            package_name: $pkg_name,
                            ecosystem: 'npm',
                            reason: 'Matched version 1.0.0',
                            reason_code: 'WITHIN_AFFECTED_RANGE',
                            fixed_version: '2.0.0'
                        }]->(pv)
                        """,
                        {
                            "sid": service_id,
                            "mid_pkg_ver": item["mid_pkg_ver"],
                            "mid_pkg_name": item["mid_pkg_name"],
                            "pkg_ver": item["pkg_ver"],
                            "pkg_name": item["pkg_name"],
                            "vuln_id": item["adv_id"],
                            "adv_id": item["adv_id"],
                            "summary": item["summary"],
                        },
                    )

        # 3. Measure FalkorDB repository query for 500 findings (iterating pages of 100)
        start_time = time.perf_counter()
        all_retrieved = []
        page_size = 100
        offset = 0

        # First request gets total count and page 1
        page_1_findings, total = repo.get_project_findings(
            project_id=project_id,
            limit=page_size,
            offset=0,
        )
        all_retrieved.extend(page_1_findings)

        # Subsequent pages
        while len(all_retrieved) < total:
            offset += page_size
            page_findings, _ = repo.get_project_findings(
                project_id=project_id,
                limit=page_size,
                offset=offset,
            )
            if not page_findings:
                break
            all_retrieved.extend(page_findings)

        total_duration = time.perf_counter() - start_time

        print(f"\n[US-201 PERFORMANCE RESULTS]")
        print(f"Total findings seeded: {total_findings}")
        print(f"Reported total count: {total}")
        print(f"Total findings retrieved across pages: {len(all_retrieved)}")
        print(f"All 500 findings loaded in: {total_duration:.4f}s (Acceptance Target: < 2.0s)")

        assert total == 500, f"Expected 500 findings, got {total}"
        assert len(all_retrieved) == 500, f"Expected 500 finding items, got {len(all_retrieved)}"
        assert total_duration < 2.0, f"500 findings loaded in {total_duration:.3f}s, exceeding 2.0s requirement"

        # 4. Measure US-202 Summary Cards query for 500 findings in FalkorDB
        summary_start = time.perf_counter()
        summary = repo.get_project_findings_summary(project_id=project_id)
        summary_duration = time.perf_counter() - summary_start

        print(f"\n[US-202 SUMMARY CARDS PERFORMANCE RESULTS]")
        print(f"Summary advisory matches: {summary['advisory_matches']}")
        print(f"Summary findings with path: {summary['findings_with_path']}")
        print(f"Summary findings without path: {summary['findings_without_path']}")
        print(f"Summary findings needing decision: {summary['findings_needing_decision']}")
        print(f"Summary query duration: {summary_duration:.4f}s (Interactive Dashboard Target: < 0.5s)")

        assert summary["advisory_matches"] == 500
        assert summary["findings_with_path"] + summary["findings_without_path"] == 500
        assert summary["findings_needing_decision"] == 500
        assert summary_duration < 1.0, f"Summary query took {summary_duration:.3f}s"

    finally:
        # Cleanup seeded nodes
        try:
            graph.query(
                "MATCH (v:Vulnerability) WHERE v.id CONTAINS $run_id DETACH DELETE v",
                {"run_id": run_id},
            )
            graph.query(
                "MATCH (pv:PackageVersion) WHERE pv.id CONTAINS $run_id DETACH DELETE pv",
                {"run_id": run_id},
            )
            graph.query(
                "MATCH (s:Service {id: $sid}) DETACH DELETE s",
                {"sid": service_id},
            )
            graph.query(
                "MATCH (p:Project {id: $pid}) DETACH DELETE p",
                {"pid": project_id},
            )
        except Exception:
            pass
