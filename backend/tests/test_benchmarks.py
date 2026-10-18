"""Automated Test Suite for US-801: Benchmark Question Set.

Acceptance Criteria verified:
AC1: Approximately 20 hand-verified questions across path existence, no-path,
     exposure, ranking, and remediation, stored in the repository.
AC2: Two team members review each answer (independent reviews with distinct IDs).
"""

from copy import deepcopy
import json
from pathlib import Path
import pytest
from httpx import AsyncClient

from vulnify.benchmarks.loader import get_default_dataset_path, get_default_schema_path, load_benchmark_dataset
from vulnify.benchmarks.models import (
    BenchmarkCase,
    BenchmarkCategory,
    BenchmarkDataset,
    DifficultyLevel,
    ExpectedAnswer,
    ReviewRecord,
    ReviewStatus,
    VerificationRecord,
    VerificationStatus,
)
from vulnify.benchmarks.validator import (
    compute_coverage,
    compute_review_summary,
    validate_benchmark_dataset,
)


# ==============================================================================
# 1. Dataset Loading and Schema Validation Tests
# ==============================================================================


def test_default_dataset_and_schema_files_exist() -> None:
    """Verifies benchmark dataset and schema files exist at expected repository paths."""
    dataset_path = get_default_dataset_path()
    schema_path = get_default_schema_path()

    assert dataset_path.exists(), f"Benchmark dataset missing at {dataset_path}"
    assert schema_path.exists(), f"Benchmark schema missing at {schema_path}"


def test_load_official_benchmark_dataset() -> None:
    """AC1: Loads the official version-controlled benchmark dataset and verifies top-level metadata."""
    dataset = load_benchmark_dataset()

    assert dataset.schema_version == "1.0.0"
    assert dataset.dataset_version == "1.0.0"
    assert "Vulnify" in dataset.dataset_title
    assert len(dataset.cases) == 20

    # Semantic validation must have zero errors
    errors = validate_benchmark_dataset(dataset)
    assert errors == [], f"Validation errors found in official dataset: {errors}"


def test_dataset_json_schema_validity() -> None:
    """Verifies that schema.json is valid JSON and describes a BenchmarkDataset."""
    schema_path = get_default_schema_path()
    content = json.loads(schema_path.read_text(encoding="utf-8"))

    assert "properties" in content
    assert "cases" in content["properties"]
    assert "dataset_version" in content["properties"]


def test_loader_rejects_missing_file(tmp_path: Path) -> None:
    """Loader raises FileNotFoundError when given a nonexistent path."""
    with pytest.raises(FileNotFoundError):
        load_benchmark_dataset(tmp_path / "nonexistent.json")


def test_loader_rejects_malformed_json(tmp_path: Path) -> None:
    """Loader raises ValueError when JSON syntax is invalid."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{ unquoted_key: invalid }", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to read benchmark dataset file|schema validation"):
        load_benchmark_dataset(bad_file)


# ==============================================================================
# 2. Coverage and Taxonomy Tests (AC1)
# ==============================================================================


def test_category_coverage_and_balance() -> None:
    """AC1: Dataset contains exactly ~20 questions covering all 5 official categories."""
    dataset = load_benchmark_dataset()
    coverage = compute_coverage(dataset)

    assert coverage.total_cases == 20

    # All 5 categories must have >= 3 cases (balanced distribution: 4 each)
    expected_categories = {
        BenchmarkCategory.PATH_EXISTS.value: 4,
        BenchmarkCategory.NO_PATH.value: 4,
        BenchmarkCategory.EXPOSURE.value: 4,
        BenchmarkCategory.RANKING.value: 4,
        BenchmarkCategory.REMEDIATION.value: 4,
    }

    assert coverage.by_category == expected_categories
    assert coverage.verified_count == 20
    assert coverage.pending_verification_count == 0
    assert coverage.blocked_verification_count == 0


def test_case_ids_are_unique_and_sequential() -> None:
    """All benchmark case IDs follow stable format BM-001 through BM-020 without duplicates."""
    dataset = load_benchmark_dataset()
    ids = [case.id for case in dataset.cases]

    assert len(ids) == len(set(ids)), "Duplicate case IDs detected"
    for i, case_id in enumerate(ids, start=1):
        assert case_id == f"BM-{i:03d}"


# ==============================================================================
# 3. Two-Person Review Invariant Tests (AC2)
# ==============================================================================


def test_all_cases_have_two_distinct_approved_reviews() -> None:
    """AC2: Every case has two independent reviews from distinct team members, all approved."""
    dataset = load_benchmark_dataset()
    reviews_summary = compute_review_summary(dataset)

    assert reviews_summary.total_cases == 20
    assert reviews_summary.fully_approved_count == 20
    assert reviews_summary.pending_first_review_count == 0
    assert reviews_summary.pending_second_review_count == 0
    assert reviews_summary.changes_requested_count == 0
    assert reviews_summary.blocked_count == 0

    for case in dataset.cases:
        assert len(case.reviews) == 2, f"{case.id} must have exactly 2 review records"
        r1, r2 = case.reviews[0], case.reviews[1]
        assert r1.reviewer_id != r2.reviewer_id, f"{case.id} has duplicate reviewer identity: {r1.reviewer_id}"
        assert r1.status == ReviewStatus.APPROVED
        assert r2.status == ReviewStatus.APPROVED
        assert len(r1.notes) >= 5
        assert len(r2.notes) >= 5


def test_validator_rejects_duplicate_reviewer_identity() -> None:
    """AC2: One reviewer cannot satisfy both review slots on a single case."""
    dataset = load_benchmark_dataset()
    tampered_dataset = deepcopy(dataset)

    # Set reviewer 2 to have same ID as reviewer 1
    case = tampered_dataset.cases[0]
    case.reviews[1].reviewer_id = case.reviews[0].reviewer_id

    errors = validate_benchmark_dataset(tampered_dataset)
    assert any("must be from distinct team members" in err for err in errors)


def test_validator_rejects_single_reviewer() -> None:
    """AC2: Case with only 1 reviewer record fails validation."""
    dataset = load_benchmark_dataset()
    tampered_dict = dataset.model_dump()
    # Remove one review
    tampered_dict["cases"][0]["reviews"] = [tampered_dict["cases"][0]["reviews"][0]]

    # Pydantic schema will reject because min_length=2
    with pytest.raises(Exception):
        BenchmarkDataset.model_validate(tampered_dict)


def test_review_summary_handles_pending_and_changes_requested() -> None:
    """Review summary accurately distinguishes pending, approved, and changes requested."""
    dataset = load_benchmark_dataset()
    test_ds = deepcopy(dataset)

    # Case 0: 1 approved, 1 pending
    test_ds.cases[0].reviews[1].status = ReviewStatus.PENDING

    # Case 1: 1 approved, 1 changes_requested
    test_ds.cases[1].reviews[1].status = ReviewStatus.CHANGES_REQUESTED

    summary = compute_review_summary(test_ds)
    assert summary.fully_approved_count == 18
    assert summary.pending_second_review_count == 1
    assert summary.changes_requested_count == 1


# ==============================================================================
# 4. Ground Truth Evidence & Safety Invariants
# ==============================================================================


def test_no_path_cases_mandate_honesty_caveats() -> None:
    """All no_path cases must forbid claiming that absence of path guarantees complete safety."""
    dataset = load_benchmark_dataset()
    no_path_cases = [c for c in dataset.cases if c.category == BenchmarkCategory.NO_PATH]

    assert len(no_path_cases) == 4
    for case in no_path_cases:
        claims = " ".join(case.expected_answer.forbidden_claims).lower()
        caveats = " ".join(case.expected_answer.required_caveats).lower()
        # Must address that absence of path does not guarantee safety
        assert "safe" in claims or "secure" in claims or "guarantee" in caveats


def test_exposure_cases_forbid_exploitability_claims() -> None:
    """All exposure cases must state architectural exposure and forbid claiming exploitability."""
    dataset = load_benchmark_dataset()
    exposure_cases = [c for c in dataset.cases if c.category == BenchmarkCategory.EXPOSURE]

    assert len(exposure_cases) == 4
    for case in exposure_cases:
        conc = case.expected_answer.conclusion.lower()
        expl = case.expected_answer.explanation.lower()
        forbidden = " ".join(case.expected_answer.forbidden_claims).lower()
        caveats = " ".join(case.expected_answer.required_caveats).lower()

        # Must mention exposure, not exploitability
        assert "exposure" in conc or "exposure" in expl or "exposure" in caveats
        assert "exploit" in forbidden or "exploit" in caveats


def test_ranking_cases_cite_scoring_reasons_and_v1_rules() -> None:
    """All ranking cases cite deterministic scoring reasons and policy rules from scoring.md."""
    dataset = load_benchmark_dataset()
    ranking_cases = [c for c in dataset.cases if c.category == BenchmarkCategory.RANKING]

    assert len(ranking_cases) == 4
    for case in ranking_cases:
        assert case.verification.method == "scoring_engine_v1.0.0"
        evidence_str = " ".join(case.expected_answer.required_evidence)
        # Must cite priority band or reason code or tie-breaker
        assert any(term in evidence_str for term in ("Priority band", "Tie-Breaker", "SEVERITY_", "PATH_"))


def test_remediation_cases_forbid_hallucinated_patches() -> None:
    """Remediation cases mandate accurate version handling and forbid inventing fictional versions."""
    dataset = load_benchmark_dataset()
    remediation_cases = [c for c in dataset.cases if c.category == BenchmarkCategory.REMEDIATION]

    assert len(remediation_cases) == 4
    nofix_case = next(c for c in remediation_cases if c.id == "BM-018")
    forbidden = " ".join(nofix_case.expected_answer.forbidden_claims).lower()
    assert "invent" in forbidden or "nonexistent" in forbidden


# ==============================================================================
# 5. REST API Integration Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_api_list_benchmark_cases(client: AsyncClient) -> None:
    """GET /api/benchmarks/cases returns all 20 cases."""
    resp = await client.get("/api/benchmarks/cases")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] == 20
    assert len(data["cases"]) == 20
    assert data["cases"][0]["id"] == "BM-001"


@pytest.mark.asyncio
async def test_api_filter_benchmark_cases_by_category(client: AsyncClient) -> None:
    """GET /api/benchmarks/cases?category=path_exists returns only path_exists cases."""
    resp = await client.get("/api/benchmarks/cases?category=path_exists")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] == 4
    for case in data["cases"]:
        assert case["category"] == "path_exists"


@pytest.mark.asyncio
async def test_api_get_single_benchmark_case(client: AsyncClient) -> None:
    """GET /api/benchmarks/cases/BM-001 returns the specific case."""
    resp = await client.get("/api/benchmarks/cases/BM-001")
    assert resp.status_code == 200
    data = resp.json()

    assert data["id"] == "BM-001"
    assert data["title"] == "Direct Dependency Path Verification"
    assert len(data["reviews"]) == 2


@pytest.mark.asyncio
async def test_api_get_benchmark_case_not_found(client: AsyncClient) -> None:
    """GET /api/benchmarks/cases/BM-999 returns 404."""
    resp = await client.get("/api/benchmarks/cases/BM-999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_api_get_benchmark_summary(client: AsyncClient) -> None:
    """GET /api/benchmarks/summary returns coverage and review progress."""
    resp = await client.get("/api/benchmarks/summary")
    assert resp.status_code == 200
    data = resp.json()

    assert data["dataset_version"] == "1.0.0"
    assert data["coverage"]["total_cases"] == 20
    assert data["coverage"]["by_category"]["ranking"] == 4
    assert data["reviews"]["fully_approved_count"] == 20
