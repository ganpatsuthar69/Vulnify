import json
from pathlib import Path
from typing import Annotated
from fastapi import APIRouter, HTTPException, Query, status

from vulnify.benchmarks.loader import load_benchmark_dataset
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
    summary="Get latest benchmark comparison run result (US-802)",
)
async def get_latest_benchmark_result() -> BenchmarkRunResult:
    """Retrieve the latest comparative evaluation result between Graph Agent and RAG Baseline."""
    latest_file = Path("benchmarks/results/latest_run.json")
    if not latest_file.exists():
        # Execute an initial run if no cached run exists
        try:
            from vulnify.benchmarks.runner import run_benchmark_comparison

            return await run_benchmark_comparison(
                dataset_path="benchmarks/benchmark_dataset.json",
                corpus_path="benchmarks/evidence_corpus.json",
                output_path="benchmarks/results/latest_run.json",
                quiet=True,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate initial benchmark comparison run: {exc}",
            ) from exc

    try:
        with latest_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return BenchmarkRunResult.model_validate(data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse benchmark results file: {exc}",
        ) from exc


@router.get(
    "/results",
    summary="List historical benchmark comparison run files",
)
async def list_benchmark_results() -> list[dict[str, str]]:
    """List available benchmark comparison run JSON artifacts."""
    results_dir = Path("benchmarks/results")
    if not results_dir.exists():
        return []

    runs = []
    for file in sorted(results_dir.glob("benchmark_run_*.json"), reverse=True):
        runs.append({"filename": file.name, "path": str(file)})
    return runs


class TriggerBenchmarkRunRequest(BaseModel):
    category: BenchmarkCategory | None = None
    dry_run: bool = False
    llm_provider: str = "auto"
    llm_model: str = "gpt-4o-mini"
    temperature: float = 0.0


@router.post(
    "/run",
    response_model=BenchmarkRunResult,
    summary="Trigger a new benchmark comparison run (US-802)",
)
async def trigger_benchmark_run(req: TriggerBenchmarkRunRequest) -> BenchmarkRunResult:
    """Execute a single-command fair comparison run between Graph Agent and RAG Baseline."""
    from vulnify.benchmarks.runner import run_benchmark_comparison

    try:
        cat_str = req.category.value if req.category else None
        target_path = "benchmarks/results/latest_run.json" if not cat_str else f"benchmarks/results/run_{cat_str}.json"
        return await run_benchmark_comparison(
            dataset_path="benchmarks/benchmark_dataset.json",
            corpus_path="benchmarks/evidence_corpus.json",
            output_path=target_path,
            category=cat_str,
            llm_provider=req.llm_provider,
            llm_model=req.llm_model,
            temperature=req.temperature,
            dry_run=req.dry_run,
            quiet=True,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Benchmark comparison execution failed: {exc}",
        ) from exc

