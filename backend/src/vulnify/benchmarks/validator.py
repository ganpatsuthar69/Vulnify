"""Semantic validation and reporting engine for Vulnify benchmarks (US-801)."""

from collections import Counter
from vulnify.benchmarks.models import (
    BenchmarkCategory,
    BenchmarkDataset,
    CoverageSummary,
    ReviewStatus,
    ReviewSummary,
    VerificationStatus,
)


def validate_benchmark_dataset(dataset: BenchmarkDataset) -> list[str]:
    """Perform thorough semantic validation across the benchmark dataset.
    
    Returns:
        List of error strings describing any violations. An empty list signifies
        full compliance with US-801 requirements.
    """
    errors: list[str] = []

    # 1. Dataset metadata checks
    if not dataset.dataset_title.strip():
        errors.append("Dataset title cannot be empty.")
    if not dataset.dataset_version.strip():
        errors.append("Dataset version cannot be empty.")

    # 2. Case uniqueness and ID constraints
    seen_ids: set[str] = set()
    category_counts = Counter()

    for idx, case in enumerate(dataset.cases, start=1):
        case_ref = f"Case {idx} [{case.id}]"

        # Unique ID
        if case.id in seen_ids:
            errors.append(f"{case_ref}: Duplicate ID '{case.id}' found in dataset.")
        seen_ids.add(case.id)

        # Category tracking
        category_counts[case.category] += 1

        # Question text
        if not case.question.strip() or len(case.question.strip()) < 10:
            errors.append(f"{case_ref}: Question text is too short or empty.")

        # Expected answer checks
        ans = case.expected_answer
        if not ans.conclusion.strip():
            errors.append(f"{case_ref}: Expected answer conclusion is missing.")
        if not ans.explanation.strip():
            errors.append(f"{case_ref}: Expected answer explanation is missing.")
        if not ans.required_evidence:
            errors.append(f"{case_ref}: Expected answer requires at least one evidence item.")
        if not ans.forbidden_claims:
            errors.append(f"{case_ref}: Expected answer requires at least one forbidden claim.")

        # Verification record checks
        ver = case.verification
        if ver.status == VerificationStatus.VERIFIED:
            if not ver.query_or_tool.strip():
                errors.append(f"{case_ref}: Verified case must specify query_or_tool used for verification.")
            if not ver.evidence_provenance.strip():
                errors.append(f"{case_ref}: Verified case must specify evidence_provenance.")
            if not ver.verification_notes.strip() or len(ver.verification_notes.strip()) < 10:
                errors.append(f"{case_ref}: Verified case must include descriptive verification_notes.")

        # AC2: Two-person review verification
        if len(case.reviews) != 2:
            errors.append(f"{case_ref}: Must contain exactly 2 reviewer records (found {len(case.reviews)}).")
        else:
            rev1, rev2 = case.reviews[0], case.reviews[1]
            if rev1.reviewer_id.strip() == rev2.reviewer_id.strip():
                errors.append(
                    f"{case_ref}: The two required reviews must be from distinct team members. "
                    f"Found duplicate reviewer_id '{rev1.reviewer_id}'."
                )
            for rev_idx, rev in enumerate((rev1, rev2), start=1):
                if not rev.reviewer_id.strip():
                    errors.append(f"{case_ref} Reviewer {rev_idx}: Missing reviewer_id.")
                if not rev.role.strip():
                    errors.append(f"{case_ref} Reviewer {rev_idx}: Missing reviewer role.")
                if not rev.notes.strip():
                    errors.append(f"{case_ref} Reviewer {rev_idx}: Missing review notes.")

    # 3. Category coverage checks (all 5 official categories must be represented)
    for cat in BenchmarkCategory:
        if category_counts[cat] == 0:
            errors.append(f"Missing benchmark coverage: Category '{cat.value}' has 0 cases.")

    return errors


def compute_coverage(dataset: BenchmarkDataset) -> CoverageSummary:
    """Calculate category, difficulty, and verification distributions from the dataset."""
    by_category = {cat.value: 0 for cat in BenchmarkCategory}
    by_difficulty: dict[str, int] = {}
    verified = 0
    pending = 0
    blocked = 0

    for case in dataset.cases:
        by_category[case.category.value] = by_category.get(case.category.value, 0) + 1
        diff = case.difficulty.value
        by_difficulty[diff] = by_difficulty.get(diff, 0) + 1

        if case.verification.status == VerificationStatus.VERIFIED:
            verified += 1
        elif case.verification.status == VerificationStatus.PENDING:
            pending += 1
        elif case.verification.status == VerificationStatus.BLOCKED:
            blocked += 1

    return CoverageSummary(
        total_cases=len(dataset.cases),
        by_category=by_category,
        by_difficulty=by_difficulty,
        verified_count=verified,
        pending_verification_count=pending,
        blocked_verification_count=blocked,
    )


def compute_review_summary(dataset: BenchmarkDataset) -> ReviewSummary:
    """Calculate review progress and approval metrics across all cases (AC2)."""
    fully_approved = 0
    pending_first = 0
    pending_second = 0
    changes_requested = 0
    blocked = 0
    reviewer_counts: dict[str, int] = {}

    for case in dataset.cases:
        approved_count = 0
        has_changes_requested = False
        has_blocked = False

        for rev in case.reviews:
            reviewer_counts[rev.reviewer_id] = reviewer_counts.get(rev.reviewer_id, 0) + 1
            if rev.status == ReviewStatus.APPROVED:
                approved_count += 1
            elif rev.status == ReviewStatus.CHANGES_REQUESTED:
                has_changes_requested = True
            elif rev.status == ReviewStatus.BLOCKED:
                has_blocked = True

        if approved_count == 2:
            fully_approved += 1
        elif has_changes_requested:
            changes_requested += 1
        elif has_blocked:
            blocked += 1
        elif approved_count == 1:
            pending_second += 1
        else:
            pending_first += 1

    return ReviewSummary(
        total_cases=len(dataset.cases),
        fully_approved_count=fully_approved,
        pending_first_review_count=pending_first,
        pending_second_review_count=pending_second,
        changes_requested_count=changes_requested,
        blocked_count=blocked,
        reviewer_counts=reviewer_counts,
    )
