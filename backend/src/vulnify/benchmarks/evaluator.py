"""Evaluation and Scoring Engine for US-802 Benchmark Comparison.

Evaluates generated answers against the US-801 hand-verified expected answers:
- Required evidence recall
- Forbidden claims penalty (safety score)
- Non-exploitability caveats presence
- Conclusion agreement
"""

import re
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from vulnify.benchmarks.models import BenchmarkCase, ExpectedAnswer
from vulnify.benchmarks.result_models import SystemExecutionResult


class CaseEvaluationMetrics(BaseModel):
    """Detailed evaluation scores for a single system on a single case."""

    model_config = ConfigDict(extra="forbid")

    system_id: str
    case_id: str
    conclusion_correct: bool
    evidence_recall: float = Field(..., ge=0.0, le=1.0)
    safety_score: float = Field(..., ge=0.0, le=1.0)
    caveats_score: float = Field(..., ge=0.0, le=1.0)
    overall_score: float = Field(..., ge=0.0, le=1.0)
    matched_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    forbidden_violations: list[str] = Field(default_factory=list)
    caveats_found: list[str] = Field(default_factory=list)


def evaluate_system_answer(case: BenchmarkCase, result: SystemExecutionResult) -> CaseEvaluationMetrics:
    """Score a system's generated answer against ground truth constraints."""
    answer_text = (result.answer or "").lower()
    expected = case.expected_answer

    # 1. Required Evidence Check
    matched_ev = []
    missing_ev = []
    for item in expected.required_evidence:
        # Check if the key keywords of the evidence item appear in the answer
        terms = re.findall(r"\b[a-zA-Z0-9_\-@\.]+\b", item.lower())
        meaningful_terms = [t for t in terms if len(t) > 2 and t not in ("the", "and", "for", "with", "from", "that")]
        if not meaningful_terms:
            matched_ev.append(item)
            continue

        match_count = sum(1 for t in meaningful_terms if t in answer_text)
        if match_count >= max(1, len(meaningful_terms) // 2):
            matched_ev.append(item)
        else:
            missing_ev.append(item)

    evidence_recall = round(len(matched_ev) / max(1, len(expected.required_evidence)), 2)

    # 2. Forbidden Claims Check
    forbidden_violations = []
    for claim in expected.forbidden_claims:
        claim_terms = re.findall(r"\b[a-zA-Z0-9_\-@\.]+\b", claim.lower())
        key_phrases = [
            "completely secure",
            "guarantee safety",
            "hallucinat",
            "direct dependency",
            "depth 1",
            "depth 2",
        ]
        # Only flag if a specific forbidden phrase is present without negation
        for phrase in key_phrases:
            if phrase in claim.lower() and phrase in answer_text:
                # Check for negation ("not a direct dependency", "does not guarantee")
                negations = [f"not {phrase}", f"no {phrase}", f"does not {phrase}", f"not a {phrase}"]
                if not any(neg in answer_text for neg in negations):
                    forbidden_violations.append(claim)
                    break

    safety_score = 1.0 if not forbidden_violations else max(0.0, round(1.0 - 0.5 * len(forbidden_violations), 2))

    # 3. Required Caveats Check (US-604 & non-exploitability rule)
    caveats_found = []
    caveat_indicators = [
        "exposure",
        "runtime exploitability",
        "does not guarantee",
        "bounded",
        "not proof",
        "caution",
        "architectural reachability",
    ]
    for caveat in expected.required_caveats:
        if any(ind in answer_text for ind in caveat_indicators):
            caveats_found.append(caveat)

    caveats_score = 1.0 if caveats_found or not expected.required_caveats else 0.0

    # 4. Conclusion Agreement
    conclusion_correct = True
    if case.category == "no_path":
        conclusion_correct = any(w in answer_text for w in ("no path", "no dependency path", "0 path", "zero", "unreferenced", "pruned", "not found"))
    elif case.category == "path_exists":
        conclusion_correct = any(w in answer_text for w in ("direct dependency", "depth 1", "depth 2", "depth 3", "shortest path", "traverses", "hops", "reaches"))
    elif case.category == "ranking":
        conclusion_correct = any(w in answer_text for w in ("highest", "medium", "priority", "band", "tie-breaker"))
    elif case.category == "remediation":
        conclusion_correct = any(w in answer_text for w in ("upgrade", "semver", "fixed", "patch", "approval", "hash", "no fixed version"))

    # Overall weighted score
    overall = (
        0.4 * (1.0 if conclusion_correct else 0.0)
        + 0.3 * evidence_recall
        + 0.2 * safety_score
        + 0.1 * caveats_score
    )

    return CaseEvaluationMetrics(
        system_id=result.system_id,
        case_id=case.id,
        conclusion_correct=conclusion_correct,
        evidence_recall=evidence_recall,
        safety_score=safety_score,
        caveats_score=caveats_score,
        overall_score=round(overall, 2),
        matched_evidence=matched_ev,
        missing_evidence=missing_ev,
        forbidden_violations=forbidden_violations,
        caveats_found=caveats_found,
    )
