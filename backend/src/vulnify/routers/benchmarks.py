"""REST API router for Vulnify Benchmark Question Set (US-801)."""

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
