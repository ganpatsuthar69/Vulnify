import json
from pathlib import Path
from typing import Annotated
from fastapi import APIRouter, HTTPException, Query, status

from vulnify.benchmarks.loader import load_benchmark_dataset, resolve_benchmark_path
from vulnify.benchmarks.models import (
    BenchmarkCase,
    BenchmarkCategory,
    CoverageSummary,
    DifficultyLevel,
    ReviewSummary,
)
from vulnify.benchmarks.result_models import BenchmarkRunResult
from vulnify.benchmarks.validator import compute_coverage, compute_review_summary
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/benchmarks", tags=["benchmarks"])


class BenchmarkCasesResponse(BaseModel):
    """Paginated or filtered response of benchmark cases."""

    cases: list[BenchmarkCase]
    total: int
    category_filter: BenchmarkCategory | None = None
    difficulty_filter: DifficultyLevel | None = None


class BenchmarkSummaryResponse(BaseModel):
    """Overview metrics of benchmark coverage and review progress."""

    dataset_version: str
    dataset_title: str
    coverage: CoverageSummary
    reviews: ReviewSummary


@router.get(
    "/cases",
    response_model=BenchmarkCasesResponse,
    summary="List benchmark question set cases",
)
async def list_benchmark_cases(
    category: Annotated[BenchmarkCategory | None, Query(description="Filter by benchmark category")] = None,
    difficulty: Annotated[DifficultyLevel | None, Query(description="Filter by difficulty level")] = None,
) -> BenchmarkCasesResponse:
    """Retrieve hand-verified benchmark cases with optional category and difficulty filtering."""
    try:
        dataset = load_benchmark_dataset()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load benchmark dataset: {exc}",
        ) from exc

    filtered = dataset.cases
    if category is not None:
        filtered = [c for c in filtered if c.category == category]
    if difficulty is not None:
        filtered = [c for c in filtered if c.difficulty == difficulty]

    return BenchmarkCasesResponse(
        cases=filtered,
        total=len(filtered),
        category_filter=category,
        difficulty_filter=difficulty,
    )


@router.get(
    "/cases/{case_id}",
    response_model=BenchmarkCase,
    summary="Get single benchmark case by ID",
)
async def get_benchmark_case(case_id: str) -> BenchmarkCase:
    """Retrieve detailed specification, expected answer, and review records for a single case."""
    try:
        dataset = load_benchmark_dataset()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load benchmark dataset: {exc}",
        ) from exc

    for case in dataset.cases:
        if case.id.upper() == case_id.upper():
            return case

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Benchmark case '{case_id}' not found.",
    )


@router.get(
    "/summary",
    response_model=BenchmarkSummaryResponse,
    summary="Get benchmark coverage and review progress summary",
)
async def get_benchmark_summary() -> BenchmarkSummaryResponse:
    """Retrieve category distribution, evidence verification, and two-person review status."""
    try:
        dataset = load_benchmark_dataset()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load benchmark dataset: {exc}",
        ) from exc

    coverage = compute_coverage(dataset)
    reviews = compute_review_summary(dataset)

    return BenchmarkSummaryResponse(
        dataset_version=dataset.dataset_version,
        dataset_title=dataset.dataset_title,
        coverage=coverage,
        reviews=reviews,
    )


@router.get(
    "/results/latest",
    response_model=BenchmarkRunResult,
    summary="Get latest benchmark comparison run result (US-802 / US-803)",
)
async def get_latest_benchmark_result() -> BenchmarkRunResult:
    """Retrieve the latest comparative evaluation result between Graph Agent and RAG Baseline.

    Returns 404 if no benchmark comparison run exists yet (AC2: 'no results yet' state).
    """
    latest_file = resolve_benchmark_path("benchmarks/results/latest_run.json", "results/latest_run.json")
    if not latest_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No benchmark run results found yet. Execute the benchmark harness first.",
        )

    try:
        with latest_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return BenchmarkRunResult.model_validate(data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse benchmark results file: {exc}",
        ) from exc


class BenchmarkRunMetadata(BaseModel):
    """Metadata summary of a stored benchmark comparison run artifact."""

    filename: str
    run_id: str
    created_at: str
    dataset_version: str
    total_cases: int
    graph_success_count: int
    rag_success_count: int


@router.get(
    "/results",
    response_model=list[BenchmarkRunMetadata],
    summary="List historical benchmark comparison run artifacts (US-803)",
)
async def list_benchmark_results() -> list[BenchmarkRunMetadata]:
    """List available benchmark comparison run JSON artifacts with metadata."""
    results_dir = resolve_benchmark_path("benchmarks/results", "results")
    if not results_dir.exists():
        return []

    runs: list[BenchmarkRunMetadata] = []
    for file in sorted(results_dir.glob("benchmark_run_*.json"), reverse=True):
        try:
            with file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            runs.append(
                BenchmarkRunMetadata(
                    filename=file.name,
                    run_id=data.get("run_id", file.stem),
                    created_at=data.get("started_at", ""),
                    dataset_version=data.get("dataset_version", "1.0.0"),
                    total_cases=data.get("summary", {}).get("total_cases", 0),
                    graph_success_count=data.get("summary", {}).get("graph_success_count", 0),
                    rag_success_count=data.get("summary", {}).get("rag_success_count", 0),
                )
            )
        except Exception:
            # Fallback for unparseable artifacts
            runs.append(
                BenchmarkRunMetadata(
                    filename=file.name,
                    run_id=file.stem,
                    created_at="",
                    dataset_version="1.0.0",
                    total_cases=0,
                    graph_success_count=0,
                    rag_success_count=0,
                )
            )
    return runs


@router.get(
    "/results/run/{filename}",
    response_model=BenchmarkRunResult,
    summary="Get specific historical benchmark comparison run result (US-803)",
)
async def get_historical_benchmark_result(filename: str) -> BenchmarkRunResult:
    """Retrieve a specific historical benchmark run by filename."""
    # Sanitize filename: only allow benchmark_run_*.json or safe alphanumeric names
    clean_name = Path(filename).name
    if not clean_name.endswith(".json") or (".." in clean_name) or ("/" in clean_name) or ("\\" in clean_name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid benchmark run filename.",
        )

    results_dir = resolve_benchmark_path("benchmarks/results", "results")
    target_file = results_dir / clean_name
    if not target_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benchmark run file '{clean_name}' not found.",
        )

    try:
        with target_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return BenchmarkRunResult.model_validate(data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse benchmark results file '{clean_name}': {exc}",
        ) from exc


class TriggerBenchmarkRunRequest(BaseModel):
    category: BenchmarkCategory | None = None
    dry_run: bool = False
    llm_provider: str | None = None
    llm_model: str | None = None
    temperature: float = 0.0


@router.post(
    "/run",
    response_model=BenchmarkRunResult,
    summary="Trigger a new benchmark comparison run (US-802)",
)
async def trigger_benchmark_run(req: TriggerBenchmarkRunRequest) -> BenchmarkRunResult:
    """Execute a single-command fair comparison run between Graph Agent and RAG Baseline."""
    from vulnify.benchmarks.runner import run_benchmark_comparison
    from vulnify.config import get_settings

    try:
        settings = get_settings()
        cat_str = req.category.value if req.category else None
        target_name = "latest_run.json" if not cat_str else f"run_{cat_str}.json"
        target_path = resolve_benchmark_path(f"benchmarks/results/{target_name}", f"results/{target_name}")
        dataset_path = resolve_benchmark_path("benchmarks/benchmark_dataset.json", "benchmark_dataset.json")
        corpus_path = resolve_benchmark_path("benchmarks/evidence_corpus.json", "evidence_corpus.json")
        return await run_benchmark_comparison(
            dataset_path=dataset_path,
            corpus_path=corpus_path,
            output_path=target_path,
            category=cat_str,
            llm_provider=req.llm_provider or settings.AGENT_LLM_PROVIDER,
            llm_model=req.llm_model or settings.AGENT_LLM_MODEL,
            temperature=req.temperature,
            dry_run=req.dry_run,
            quiet=True,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Benchmark comparison execution failed: {exc}",
        ) from exc


from vulnify.benchmarks.graph_path_benchmark import (
    GraphPathBenchmarkConfig,
    GraphPathBenchmarkResult,
    load_latest_graph_path_benchmark,
    run_graph_path_benchmark,
)


@router.get(
    "/performance/graph-path",
    response_model=GraphPathBenchmarkResult,
    summary="Get latest graph-path query performance benchmark result (US-903)",
)
async def get_graph_path_performance_benchmark() -> GraphPathBenchmarkResult:
    """Retrieve the latest graph-path query P95 performance benchmark result.

    Returns 404 if no benchmark run exists yet.
    """
    res = load_latest_graph_path_benchmark()
    if res is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No graph-path benchmark results found yet. Execute the benchmark first.",
        )
    return res


@router.post(
    "/performance/graph-path/run",
    response_model=GraphPathBenchmarkResult,
    summary="Trigger graph-path query performance benchmark run (US-903)",
)
async def trigger_graph_path_performance_run(
    config: GraphPathBenchmarkConfig | None = None,
) -> GraphPathBenchmarkResult:
    """Execute the graph-path performance benchmark and return verified P95 latency metrics."""
    try:
        return run_graph_path_benchmark(config=config)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Graph-path benchmark execution failed: {exc}",
        ) from exc

