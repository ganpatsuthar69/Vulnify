"""US-903 Graph-Path Query Performance Benchmark Module.

Benchmarks the production FalkorDB graph-path traversal query (get_project_finding_paths)
over a seeded graph of at least 5,000 package versions, calculating high-resolution
median and 95th percentile (P95) latencies against the 1-second acceptance target.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any
from pydantic import BaseModel, Field

from vulnify.benchmarks.loader import resolve_benchmark_path
from vulnify.graph.client import GraphClient, get_graph_client, load_query


class PathQueryMetric(BaseModel):
    """Timing and result metric for a single graph-path query execution."""

    iteration: int
    duration_ms: float
    success: bool
    path_count: int = 0
    error: str | None = None


class GraphPathBenchmarkConfig(BaseModel):
    """Configuration parameters for the graph-path performance benchmark."""

    target_p95_ms: float = Field(default=1000.0, description="US-903 P95 target threshold in ms (< 1s)")
    iterations: int = Field(default=50, ge=5, description="Number of measured query iterations")
    warmup_iterations: int = Field(default=5, ge=0, description="Warm-up runs excluded from statistics")
    query_depth_limit: int = Field(default=8, description="Bounded Cypher traversal depth (*1..8)")
    path_limit: int = Field(default=5, description="Maximum paths returned per query")


class GraphPathBenchmarkResult(BaseModel):
    """Authoritative result record for the US-903 graph-path performance benchmark."""

    schema_version: str = "1.0.0"
    operation_name: str = "get_project_finding_paths"
    query_provenance: str = "backend/src/vulnify/graph/queries/get_project_finding_paths.cypher"
    executed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = Field(..., description="'passed', 'failed', or 'unavailable'")
    dataset_description: str = "Seeded dependency graph with >= 5,000 package versions"
    total_packages_in_graph: int = 0
    iterations_measured: int = 0
    warmup_iterations: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    median_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    mean_latency_ms: float = 0.0
    latency_units: str = "milliseconds"
    target_p95_ms: float = 1000.0
    passed_target: bool = False
    details: list[PathQueryMetric] = Field(default_factory=list)
    error_summary: str | None = None


def compute_percentile(data: list[float], percentile: float) -> float:
    """Compute an accurate percentile from a list of float measurements using linear interpolation.

    Args:
        data: List of measured latency numbers.
        percentile: Target percentile between 0.0 and 100.0.

    Returns:
        Interpolated percentile value rounded to 3 decimal places.
    """
    if not data:
        raise ValueError("Cannot calculate percentile on an empty sample set.")
    if not (0.0 <= percentile <= 100.0):
        raise ValueError(f"Percentile must be between 0.0 and 100.0, got {percentile}")

    sorted_data = sorted(data)
    n = len(sorted_data)
    if n == 1:
        return round(sorted_data[0], 3)

    k = (n - 1) * (percentile / 100.0)
    floor_idx = int(k)
    ceil_idx = floor_idx + 1

    if ceil_idx >= n:
        return round(sorted_data[-1], 3)

    fraction = k - floor_idx
    val = sorted_data[floor_idx] + fraction * (sorted_data[ceil_idx] - sorted_data[floor_idx])
    return round(val, 3)


def execute_graph_path_query(
    graph: Any,
    query_str: str,
    service_id: str,
    target_id: str,
    limit: int = 5,
) -> tuple[float, bool, int, str | None]:
    """Execute a single production graph path traversal query and measure latency.

    Uses high-resolution monotonic clock (time.perf_counter).
    Returns (duration_ms, success, path_count, error_message).
    """
    start_time = time.perf_counter()
    try:
        res = graph.query(
            query_str,
            {
                "service_id": service_id,
                "target_id": target_id,
                "limit": limit,
            },
        )
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        path_count = len(res.result_set) if res and hasattr(res, "result_set") else 0
        return round(duration_ms, 3), True, path_count, None
    except Exception as exc:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return round(duration_ms, 3), False, 0, str(exc)


def run_graph_path_benchmark(
    client: GraphClient | None = None,
    config: GraphPathBenchmarkConfig | None = None,
    service_id: str | None = None,
    target_id: str | None = None,
    save_artifact: bool = True,
) -> GraphPathBenchmarkResult:
    """Run the reproducible graph-path performance benchmark.

    Evaluates P95 and median latency against the 1.0s target.
    """
    cfg = config or GraphPathBenchmarkConfig()
    graph_client = client or get_graph_client()

    query_str = load_query("get_project_finding_paths.cypher")

    # 1. Connect and verify FalkorDB availability
    try:
        graph = graph_client.get_graph()
        ping_res = graph.query("RETURN 1")
        if not ping_res:
            raise RuntimeError("Graph returned empty ping response.")
    except Exception as exc:
        result = GraphPathBenchmarkResult(
            status="unavailable",
            error_summary=f"FalkorDB graph is unavailable: {exc}",
            target_p95_ms=cfg.target_p95_ms,
            passed_target=False,
        )
        if save_artifact:
            save_benchmark_result(result)
        return result

    # 2. Inspect graph size and find or verify candidate paths
    total_packages = 0
    try:
        count_res = graph.query("MATCH (pv:PackageVersion) RETURN count(pv) AS cnt")
        if count_res and count_res.result_set:
            total_packages = int(count_res.result_set[0][0])
    except Exception:
        total_packages = 0

    # Auto-discover representative service_id and target_id if not supplied
    resolved_service_id = service_id
    resolved_target_id = target_id

    if not resolved_service_id or not resolved_target_id:
        try:
            sample_res = graph.query(
                """
                MATCH (s:Service)-[:DEPENDS_ON]->(pv:PackageVersion)
                RETURN s.id AS sid, pv.id AS pvid
                LIMIT 1
                """
            )
            if sample_res and sample_res.result_set:
                resolved_service_id = str(sample_res.result_set[0][0])
                resolved_target_id = str(sample_res.result_set[0][1])
        except Exception:
            pass

    if not resolved_service_id or not resolved_target_id:
        result = GraphPathBenchmarkResult(
            status="failed",
            total_packages_in_graph=total_packages,
            error_summary="No suitable service-to-package dependency paths found in graph to benchmark.",
            target_p95_ms=cfg.target_p95_ms,
            passed_target=False,
        )
        if save_artifact:
            save_benchmark_result(result)
        return result

    # 3. Warm-up Phase (EXCLUDED from recorded metrics)
    for _ in range(cfg.warmup_iterations):
        execute_graph_path_query(
            graph=graph,
            query_str=query_str,
            service_id=resolved_service_id,
            target_id=resolved_target_id,
            limit=cfg.path_limit,
        )

    # 4. Measured Execution Phase
    metrics: list[PathQueryMetric] = []
    durations: list[float] = []

    for i in range(cfg.iterations):
        duration_ms, success, path_count, err = execute_graph_path_query(
            graph=graph,
            query_str=query_str,
            service_id=resolved_service_id,
            target_id=resolved_target_id,
            limit=cfg.path_limit,
        )
        metrics.append(
            PathQueryMetric(
                iteration=i + 1,
                duration_ms=duration_ms,
                success=success,
                path_count=path_count,
                error=err,
            )
        )
        if success:
            durations.append(duration_ms)

    successful_count = len(durations)
    failed_count = cfg.iterations - successful_count

    if successful_count == 0:
        result = GraphPathBenchmarkResult(
            status="failed",
            total_packages_in_graph=total_packages,
            iterations_measured=cfg.iterations,
            warmup_iterations=cfg.warmup_iterations,
            successful_queries=0,
            failed_queries=failed_count,
            error_summary="All measured graph path query iterations failed.",
            target_p95_ms=cfg.target_p95_ms,
            passed_target=False,
            details=metrics,
        )
        if save_artifact:
            save_benchmark_result(result)
        return result

    median_ms = compute_percentile(durations, 50.0)
    p95_ms = compute_percentile(durations, 95.0)
    min_ms = round(min(durations), 3)
    max_ms = round(max(durations), 3)
    mean_ms = round(sum(durations) / successful_count, 3)
    passed_target = p95_ms <= cfg.target_p95_ms

    result = GraphPathBenchmarkResult(
        status="passed" if passed_target else "failed",
        total_packages_in_graph=total_packages,
        iterations_measured=cfg.iterations,
        warmup_iterations=cfg.warmup_iterations,
        successful_queries=successful_count,
        failed_queries=failed_count,
        median_latency_ms=median_ms,
        p95_latency_ms=p95_ms,
        min_latency_ms=min_ms,
        max_latency_ms=max_ms,
        mean_latency_ms=mean_ms,
        target_p95_ms=cfg.target_p95_ms,
        passed_target=passed_target,
        details=metrics,
    )

    if save_artifact:
        save_benchmark_result(result)

    return result


def save_benchmark_result(result: GraphPathBenchmarkResult) -> Path:
    """Save graph-path benchmark result to benchmarks/results/graph_path_benchmark.json."""
    output_path = resolve_benchmark_path("benchmarks/results/graph_path_benchmark.json", "results/graph_path_benchmark.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result.model_dump(), f, indent=2)
    return output_path


def load_latest_graph_path_benchmark() -> GraphPathBenchmarkResult | None:
    """Load latest stored graph-path benchmark artifact if available."""
    target_path = resolve_benchmark_path("benchmarks/results/graph_path_benchmark.json", "results/graph_path_benchmark.json")
    if not target_path.exists():
        return None
    try:
        with target_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return GraphPathBenchmarkResult.model_validate(data)
    except Exception:
        return None
