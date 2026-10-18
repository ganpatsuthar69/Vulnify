"""Tool: get_finding_details (US-601 AC-1 / AC-2).

Purpose:
Retrieves comprehensive evidence, advisory description, version matching criteria,
provenance, and priority reasons for a single vulnerability finding.
Wraps the parameterized 'get_project_finding_detail' query.
"""

from datetime import datetime, timezone
import time
from typing import Any
from pydantic import BaseModel, Field

from vulnify.agent.registry import ToolDefinition
from vulnify.agent.schemas import TraceFragment
from vulnify.agent.trust_boundary import delimit_untrusted_data, sanitize_untrusted_text
from vulnify.graph.vulnerability_repository import get_vulnerability_repository


class GetFindingDetailsInput(BaseModel):
    """Input parameters for finding details retrieval."""

    project_id: str = Field(..., description="Unique project identifier", min_length=1)
    finding_id: str = Field(
        ...,
        description="Finding identifier (find-... hash) or advisory ID (e.g. GHSA-..., OSV-...)",
        min_length=1,
    )


class FindingDetailItem(BaseModel):
    """Normalized evidence and context payload for a single finding."""

    id: str
    project_id: str
    service_id: str
    service_name: str
    advisory_id: str
    advisory_summary: str
    advisory_details: str
    delimited_advisory_data: str = Field(
        default="",
        description="Delimited and sanitized untrusted advisory text with explicit agent notice (US-604)",
    )
    severity: str
    priority: str
    priority_reasons: list[str] = Field(default_factory=list)
    scoring_version: str
    status: str
    package_name: str
    package_version: str
    ecosystem: str
    matched_range: str | None = None
    match_reason: str = ""
    reason_code: str = ""
    fixed_version: str | None = None
    advisory_fixed_versions: list[str] = Field(default_factory=list)
    path_depth: int | None = None
    path_status: str
    aliases: list[str] = Field(default_factory=list)
    source_url: str = ""
    retrieved_at: int | None = None
    review_required: bool = False
    review_reason: str | None = None
    change_category: str | None = None
    triaged_by: str | None = None
    triaged_at: int | None = None
    triage_justification: str | None = None
    reviewed_at: int | None = None


class GetFindingDetailsResult(BaseModel):
    """Result returned by get_finding_details tool."""

    found: bool
    finding: FindingDetailItem | None = None
    trace: TraceFragment


async def handle_get_finding_details(inputs: GetFindingDetailsInput) -> GetFindingDetailsResult:
    """Execute get_project_finding_detail query and return typed finding evidence."""
    start = time.perf_counter()
    repo = get_vulnerability_repository()

    finding_data = repo.get_project_finding_detail(
        project_id=inputs.project_id,
        finding_id=inputs.finding_id,
    )

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    now = int(datetime.now(timezone.utc).timestamp())

    if not finding_data:
        trace = TraceFragment(
            tool_name="get_finding_details",
            query_id="get_project_finding_detail",
            inputs=inputs.model_dump(),
            result_summary=f"Finding '{inputs.finding_id}' not found in project '{inputs.project_id}'.",
            duration_ms=duration_ms,
            record_count=0,
            evaluated_at=now,
            outcome="empty",
            warning=f"No finding matching '{inputs.finding_id}' exists for project '{inputs.project_id}'.",
        )
        return GetFindingDetailsResult(
            found=False,
            finding=None,
            trace=trace,
        )

    raw_summary = finding_data.get("advisory_summary", "")
    raw_details = finding_data.get("advisory_details", "")
    combined_adv_text = raw_details or raw_summary

    delimited_adv = delimit_untrusted_data(
        combined_adv_text,
        source="osv_advisory",
        label=finding_data.get("advisory_id"),
    )

    review_req = bool(finding_data.get("review_required", False))
    review_rsn = finding_data.get("review_reason")

    item = FindingDetailItem(
        id=finding_data.get("id", inputs.finding_id),
        project_id=inputs.project_id,
        service_id=finding_data.get("service_id", ""),
        service_name=finding_data.get("service_name", ""),
        advisory_id=finding_data.get("advisory_id", ""),
        advisory_summary=sanitize_untrusted_text(raw_summary),
        advisory_details=sanitize_untrusted_text(raw_details),
        delimited_advisory_data=delimited_adv,
        severity=finding_data.get("severity", "UNKNOWN"),
        priority=finding_data.get("priority", "unknown"),
        priority_reasons=finding_data.get("priority_reasons", []),
        scoring_version=finding_data.get("scoring_version", "v1.0.0"),
        status=finding_data.get("status", "open"),
        package_name=finding_data.get("package_name", ""),
        package_version=finding_data.get("package_version", ""),
        ecosystem=finding_data.get("ecosystem", ""),
        matched_range=finding_data.get("matched_range"),
        match_reason=finding_data.get("match_reason", ""),
        reason_code=finding_data.get("reason_code", ""),
        fixed_version=finding_data.get("fixed_version"),
        advisory_fixed_versions=finding_data.get("advisory_fixed_versions", []),
        path_depth=finding_data.get("path_depth"),
        path_status=finding_data.get("path_status", "no_path_found"),
        aliases=finding_data.get("aliases", []),
        source_url=finding_data.get("source_url", ""),
        retrieved_at=finding_data.get("retrieved_at"),
        review_required=review_req,
        review_reason=review_rsn,
        change_category=finding_data.get("change_category"),
        triaged_by=finding_data.get("triaged_by"),
        triaged_at=finding_data.get("triaged_at"),
        triage_justification=finding_data.get("triage_justification"),
        reviewed_at=finding_data.get("reviewed_at"),
    )

    review_note = f" [NEEDS REVIEW: {review_rsn}]" if review_req and review_rsn else ""
    trace = TraceFragment(
        tool_name="get_finding_details",
        query_id="get_project_finding_detail",
        inputs=inputs.model_dump(),
        result_summary=(
            f"Found details for finding '{item.id}' ({item.advisory_id} on {item.package_name}@{item.package_version}). "
            f"Priority: {item.priority}, Path Status: {item.path_status}, Status: {item.status}{review_note}."
        ),
        duration_ms=duration_ms,
        record_count=1,
        evaluated_at=now,
        outcome="success",
        evidence_references=[item.advisory_id],
    )

    return GetFindingDetailsResult(
        found=True,
        finding=item,
        trace=trace,
    )


get_finding_details_tool = ToolDefinition(
    name="get_finding_details",
    description="Retrieve full evidence, advisory text, version match reason, and priority for a specific finding.",
    classification="read_only",
    input_model=GetFindingDetailsInput,
    output_model=GetFindingDetailsResult,
    handler=handle_get_finding_details,
    query_id="get_project_finding_detail",
    requires_approval=False,
)
