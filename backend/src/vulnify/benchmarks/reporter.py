"""CLI and reporting tool for Vulnify Benchmark Question Set (US-801)."""

import sys
from vulnify.benchmarks.loader import load_benchmark_dataset
from vulnify.benchmarks.models import BenchmarkDataset
from vulnify.benchmarks.validator import (
    compute_coverage,
    compute_review_summary,
    validate_benchmark_dataset,
)


def generate_benchmark_report(dataset: BenchmarkDataset) -> str:
    """Generate a clean, structured text report of benchmark coverage and review status."""
    coverage = compute_coverage(dataset)
    reviews = compute_review_summary(dataset)

    lines: list[str] = [
        "=" * 78,
        f" Vulnify Benchmark Question Set Report (US-801)",
        f" Dataset: {dataset.dataset_title} (v{dataset.dataset_version})",
        "=" * 78,
        "",
        "--- Category Coverage ---",
        f" Total Cases:             {coverage.total_cases}",
    ]

    for cat, count in coverage.by_category.items():
        pct = (count / coverage.total_cases * 100) if coverage.total_cases else 0.0
        lines.append(f"   • {cat:<24} {count:>3} cases ({pct:>5.1f}%)")

    lines.extend([
        "",
        "--- Difficulty Breakdown ---",
    ])
    for diff, count in coverage.by_difficulty.items():
        lines.append(f"   • {diff.capitalize():<24} {count:>3} cases")

    lines.extend([
        "",
        "--- Ground Truth Evidence Verification ---",
        f"   • Verified Cases:          {coverage.verified_count:>3} / {coverage.total_cases}",
        f"   • Pending Verification:    {coverage.pending_verification_count:>3}",
        f"   • Blocked:                 {coverage.blocked_verification_count:>3}",
        "",
        "--- Two-Person Human Review Status (AC2) ---",
        f"   • Fully Approved (2/2):    {reviews.fully_approved_count:>3} / {reviews.total_cases}",
        f"   • Awaiting 2nd Review:     {reviews.pending_second_review_count:>3}",
        f"   • Awaiting 1st Review:     {reviews.pending_first_review_count:>3}",
        f"   • Changes Requested:       {reviews.changes_requested_count:>3}",
        f"   • Blocked:                 {reviews.blocked_count:>3}",
        "",
        "--- Reviewer Participation ---",
    ])
    for rev_id, count in reviews.reviewer_counts.items():
        lines.append(f"   • {rev_id:<26} {count:>3} reviews")

    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> None:
    """Command-line interface to inspect and validate the benchmark dataset."""
    try:
        dataset = load_benchmark_dataset()
    except Exception as exc:
        print(f"Error loading benchmark dataset: {exc}", file=sys.stderr)
        sys.exit(1)

    errors = validate_benchmark_dataset(dataset)
    report = generate_benchmark_report(dataset)
    print(report)

    if errors:
        print("\nVALIDATION VIOLATIONS DETECTED:", file=sys.stderr)
        for err in errors:
            print(f"  [X] {err}", file=sys.stderr)
        sys.exit(2)
    else:
        print("\nAll benchmark validation checks PASSED (100% compliant with US-801).")
        sys.exit(0)


if __name__ == "__main__":
    main()
