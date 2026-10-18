"""Comprehensive Unit and Integration Tests for US-903 Graph-Path Benchmark.

Verifies:
1. Percentile calculations (median, P95) using controlled test distributions.
2. Warm-up exclusion from recorded metrics.
3. Failure and timeout handling without corrupting latency figures.
4. Empty sample handling.
5. Database unavailable and missing graph error handling.
6. Benchmark result schema serialization.
7. Real FalkorDB graph-path query execution over seeded graph under 1 second P95.
"""

from unittest.mock import MagicMock
import pytest
from httpx import AsyncClient

from vulnify.benchmarks.graph_path_benchmark import (
    GraphPathBenchmarkConfig,
    GraphPathBenchmarkResult,
    compute_percentile,
    execute_graph_path_query,
    run_graph_path_benchmark,
)
from vulnify.graph.client import get_graph_client


# ==============================================================================
# 1. Statistical Calculation Tests
# ==============================================================================


def test_compute_percentile_known_distributions() -> None:
    """Accurately computes percentiles using linear interpolation on controlled samples."""
    # 1 to 100 integers
    data = [float(x) for x in range(1, 101)]

    # 50th percentile (median) of 1..100 is 50.5
    median = compute_percentile(data, 50.0)
    assert median == 50.5

    # 95th percentile of 1..100: (99 * 0.95) = 94.05 -> 1 + 94.05 = 95.05
    p95 = compute_percentile(data, 95.0)
    assert p95 == 95.05

    # Edge percentiles
    assert compute_percentile(data, 0.0) == 1.0
    assert compute_percentile(data, 100.0) == 100.0


def test_compute_percentile_single_element() -> None:
    """Single element sample returns exactly that value for any percentile."""
    assert compute_percentile([42.5], 50.0) == 42.5
    assert compute_percentile([42.5], 95.0) == 42.5
    assert compute_percentile([42.5], 99.0) == 42.5


def test_compute_percentile_identical_values() -> None:
    """Repeated identical latency values return that constant value."""
    sample = [5.0, 5.0, 5.0, 5.0, 5.0]
    assert compute_percentile(sample, 50.0) == 5.0
    assert compute_percentile(sample, 95.0) == 5.0


def test_compute_percentile_rejects_empty_data() -> None:
    """Raises ValueError when given an empty sample list."""
    with pytest.raises(ValueError, match="empty sample set"):
        compute_percentile([], 95.0)


def test_compute_percentile_rejects_invalid_bounds() -> None:
    """Raises ValueError when percentile is outside [0, 100]."""
    with pytest.raises(ValueError, match="Percentile must be between 0.0 and 100.0"):
        compute_percentile([1.0, 2.0], -1.0)

    with pytest.raises(ValueError, match="Percentile must be between 0.0 and 100.0"):
        compute_percentile([1.0, 2.0], 101.0)


# ==============================================================================
# 2. Execution and Error Handling Tests
# ==============================================================================


def test_execute_graph_path_query_records_failure_truthfully() -> None:
    """Failed query records success=False and does not report fake zero latency."""
    mock_graph = MagicMock()
    mock_graph.query.side_effect = RuntimeError("FalkorDB timeout during traversal")

    duration_ms, success, count, err = execute_graph_path_query(
        graph=mock_graph,
        query_str="MATCH ...",
        service_id="svc-1",
        target_id="npm:pkg@1.0.0",
    )

    assert success is False
    assert count == 0
    assert duration_ms >= 0.0
    assert "timeout during traversal" in str(err)


def test_run_benchmark_handles_database_unavailable() -> None:
    """When FalkorDB connection fails, returns status='unavailable' with error summary."""
    mock_client = MagicMock()
    mock_client.get_graph.side_effect = ConnectionError("Could not connect to Redis at localhost:6379")

    result = run_graph_path_benchmark(client=mock_client, save_artifact=False)

    assert result.status == "unavailable"
    assert result.passed_target is False
    assert result.error_summary is not None
    assert "unavailable" in result.error_summary.lower()


def test_run_benchmark_handles_missing_graph_data() -> None:
    """When graph exists but contains no dependency paths, reports explicit failure."""
    mock_graph = MagicMock()
    # Ping succeeds
    mock_graph.query.side_effect = [
        [1],  # RETURN 1
        MagicMock(result_set=[[0]]),  # count(pv) = 0
        MagicMock(result_set=[]),  # sample path query returns empty
    ]
    mock_client = MagicMock()
    mock_client.get_graph.return_value = mock_graph

    result = run_graph_path_benchmark(client=mock_client, save_artifact=False)

    assert result.status == "failed"
    assert result.passed_target is False
    assert "no suitable service-to-package dependency paths" in str(result.error_summary).lower()


def test_run_benchmark_warmup_excluded_from_metrics() -> None:
    """Warmup iterations are executed separately and not counted in iterations_measured."""
    mock_graph = MagicMock()
    mock_graph.query.side_effect = [
        [1],  # ping
        MagicMock(result_set=[[5000]]),  # count
        MagicMock(result_set=[["svc-1", "npm:lodash@4.17.21"]]),  # sample
    ] + [
        MagicMock(result_set=[["mock_path"]]) for _ in range(20)  # warm-up + measured
    ]
    mock_client = MagicMock()
    mock_client.get_graph.return_value = mock_graph

    cfg = GraphPathBenchmarkConfig(iterations=10, warmup_iterations=3)
    result = run_graph_path_benchmark(client=mock_client, config=cfg, save_artifact=False)

    assert result.iterations_measured == 10
    assert result.warmup_iterations == 3
    assert len(result.details) == 10
    assert result.successful_queries == 10


def test_benchmark_result_serialization() -> None:
    """GraphPathBenchmarkResult validates and serializes to JSON without data loss."""
    res = GraphPathBenchmarkResult(
        status="passed",
        total_packages_in_graph=5200,
        iterations_measured=50,
        warmup_iterations=5,
        successful_queries=50,
        failed_queries=0,
        median_latency_ms=12.45,
        p95_latency_ms=38.92,
        min_latency_ms=8.10,
        max_latency_ms=45.20,
        mean_latency_ms=15.22,
        target_p95_ms=1000.0,
        passed_target=True,
    )

    data = res.model_dump()
    assert data["status"] == "passed"
    assert data["p95_latency_ms"] == 38.92
    assert data["target_p95_ms"] == 1000.0
    assert data["passed_target"] is True

    # Re-validate
    reloaded = GraphPathBenchmarkResult.model_validate(data)
    assert reloaded.median_latency_ms == 12.45
    assert reloaded.passed_target is True


# ==============================================================================
# 3. FalkorDB Live Integration Test (US-903)
# ==============================================================================


@pytest.fixture
def falkor_client():
    try:
        client = get_graph_client()
        graph = client.get_graph()
        graph.query("RETURN 1")
        return client
    except Exception as exc:
        pytest.skip(f"FalkorDB is not reachable: {exc}")


def test_graph_path_benchmark_against_falkordb(falkor_client) -> None:
    """US-903 Acceptance Criterion: Path queries stay under 1 second (95th percentile)."""
    graph = falkor_client.get_graph()

    # Seed a controlled 3-tier dependency path structure to benchmark
    test_svc = "svc-perf-benchmark"
    test_target = "npm:perf-vulnerable-leaf@1.0.0"

    try:
        graph.query(
            """
            MERGE (s:Service {id: $sid, name: 'perf-benchmark-service', internet_facing: true})
            MERGE (m1:PackageVersion {id: 'npm:perf-mid-1@1.0.0', name: 'perf-mid-1', version: '1.0.0', ecosystem: 'npm'})
            MERGE (m2:PackageVersion {id: 'npm:perf-mid-2@1.0.0', name: 'perf-mid-2', version: '1.0.0', ecosystem: 'npm'})
            MERGE (pv:PackageVersion {id: $tid, name: 'perf-vulnerable-leaf', version: '1.0.0', ecosystem: 'npm'})
            MERGE (s)-[:DEPENDS_ON {origin: 'manifest'}]->(m1)
            MERGE (m1)-[:DEPENDS_ON {origin: 'lockfile'}]->(m2)
            MERGE (m2)-[:DEPENDS_ON {origin: 'lockfile'}]->(pv)
            """,
            {"sid": test_svc, "tid": test_target},
        )

        cfg = GraphPathBenchmarkConfig(
            target_p95_ms=1000.0,
            iterations=25,
            warmup_iterations=3,
        )

        result = run_graph_path_benchmark(
            client=falkor_client,
            config=cfg,
            service_id=test_svc,
            target_id=test_target,
            save_artifact=True,
        )

        print(f"\n[US-903 GRAPH-PATH BENCHMARK RESULTS]")
        print(f"Status: {result.status}")
        print(f"Iterations: {result.iterations_measured} (Warm-up: {result.warmup_iterations})")
        print(f"Successful Queries: {result.successful_queries}")
        print(f"Median Latency: {result.median_latency_ms:.3f}ms")
        print(f"P95 Latency: {result.p95_latency_ms:.3f}ms (Target: < 1000.0ms)")
        print(f"Passed Target (< 1.0s): {result.passed_target}")

        assert result.status == "passed", f"Benchmark failed with summary: {result.error_summary}"
        assert result.successful_queries == 25
        assert result.passed_target is True
        assert result.p95_latency_ms < 1000.0, f"P95 latency was {result.p95_latency_ms}ms, exceeding 1000ms"
        assert result.median_latency_ms < 1000.0

    finally:
        try:
            graph.query("MATCH (s:Service {id: $sid}) DETACH DELETE s", {"sid": test_svc})
            graph.query("MATCH (pv:PackageVersion {id: $tid}) DETACH DELETE pv", {"tid": test_target})
            graph.query("MATCH (pv:PackageVersion {id: 'npm:perf-mid-1@1.0.0'}) DETACH DELETE pv")
            graph.query("MATCH (pv:PackageVersion {id: 'npm:perf-mid-2@1.0.0'}) DETACH DELETE pv")
        except Exception:
            pass
