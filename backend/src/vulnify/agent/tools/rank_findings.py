"""Tool: rank_findings (US-601 AC-1 / AC-2).

Purpose:
Ranks and groups vulnerability findings for a project according to Vulnify's deterministic
priority scoring policy (v1.0.0), providing priority bands, reasons, and tie-broken order.
Wraps the parameterized finding query and deterministic scoring engine.
"""

from datetime import datetime, timezone
import time
from typing import Any
from pydantic import BaseModel, Field

from vulnify.agent.registry import ToolDefinition
from vulnify.agent.schemas import TraceFragment
from vulnify.graph.vulnerability_repository import get_vulnerability_repository
from vulnify.scoring.engine import SCORING_VERSION, finding_sort_key


class RankFindingsInput(BaseModel):
    """Input parameters for ranking project findings."""

    project_id: str = Field(..., description="Unique project identifier", min_length=1)
    service_id: str | None = Field(default=None, description="Optional service scope filter")
    limit: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Maximum number of ranked findings to return (bounded 1..200)",
    )


class RankedFindingItem(BaseModel):
    """A single finding ordered by deterministic priority scoring."""

    rank: int
    id: str
    advisory_id: str
    package_name: str
    package_version: str
    service_name: str
    priority: str
    priority_reasons: list[str] = Field(default_factory=list)
    severity: str
    path_depth: int | None = None
    path_status: str
    fixed_version: str | None = None
    status: str
    review_required: bool = False
    review_reason: str | None = None


class PriorityBandDistribution(BaseModel):
    """Count of findings across each priority band."""

    highest: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class RankFindingsResult(BaseModel):
    """Result returned by rank_findings tool."""

    project_id: str
    scoring_version: str
    total_findings: int
    distribution: PriorityBandDistribution
    ranked_findings: list[RankedFindingItem]
    trace: TraceFragment


async def handle_rank_findings(inputs: RankFindingsInput) -> RankFindingsResult:
    """Retrieve and deterministically rank project findings using scoring engine."""
    start = time.perf_counter()
    repo = get_vulnerability_repository()
    now = int(datetime.now(timezone.utc).timestamp())

    raw_items, total = repo.get_project_findings(
        project_id=inputs.project_id,
        service_id=inputs.service_id,
        limit=inputs.limit,
        offset=0,
        sort_by="priority",
    )

    # Apply strict deterministic sort key
    sorted_items = sorted(raw_items, key=finding_sort_key)

    distribution = PriorityBandDistribution()
    ranked_findings: list[RankedFindingItem] = []

    for idx, item in enumerate(sorted_items, start=1):
        p_raw = str(item.get("priority", "unknown")).lower()
        if p_raw == "highest":
            distribution.highest += 1
        elif p_raw == "high":
            distribution.high += 1
        elif p_raw == "medium":
            distribution.medium += 1
        elif p_raw == "low":
            distribution.low += 1
        else:
            distribution.unknown += 1

        ranked_findings.append(
            RankedFindingItem(
                rank=idx,
                id=item["id"],
                advisory_id=item.get("advisory_id", ""),
                package_name=item.get("package_name", ""),
                package_version=item.get("package_version", ""),
                service_name=item.get("service_name", ""),
                priority=item.get("priority", "unknown"),
                priority_reasons=item.get("priority_reasons", []),
                severity=item.get("severity", "UNKNOWN"),
                path_depth=item.get("path_depth"),
                path_status=item.get("path_status", "no_path_found"),
                fixed_version=item.get("fixed_version"),
                status=item.get("status", "open"),
                review_required=bool(item.get("review_required", False)),
                review_reason=item.get("review_reason"),
            )
        )

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    summary = (
        f"Ranked {len(ranked_findings)} finding(s) under {SCORING_VERSION} policy for project '{inputs.project_id}'. "
        f"Distribution: Highest={distribution.highest}, High={distribution.high}, "
        f"Medium={distribution.medium}, Low={distribution.low}, Unknown={distribution.unknown}."
    )

    trace = TraceFragment(
        tool_name="rank_findings",
        query_id="rank_project_findings",
        inputs=inputs.model_dump(),
        result_summary=summary,
        duration_ms=duration_ms,
        record_count=len(ranked_findings),
        evaluated_at=now,
        outcome="success" if ranked_findings else "empty",
        evidence_references=[f.advisory_id for f in ranked_findings[:10]],
    )

    return RankFindingsResult(
        project_id=inputs.project_id,
        scoring_version=SCORING_VERSION,
        total_findings=total,
        distribution=distribution,
        ranked_findings=ranked_findings,
        trace=trace,
    )


rank_findings_tool = ToolDefinition(
    name="rank_findings",
    description="Ranks and groups vulnerability findings using the deterministic priority policy (v1.0.0).",
    classification="read_only",
    input_model=RankFindingsInput,
    output_model=RankFindingsResult,
    handler=handle_rank_findings,
    query_id="rank_project_findings",
    requires_approval=False,
)
