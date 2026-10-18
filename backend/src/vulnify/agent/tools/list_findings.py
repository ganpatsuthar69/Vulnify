"""Tool: list_findings (US-601 AC-1 / AC-2).

Purpose:
Retrieves server-paginated, deduplicated vulnerability findings for a project
with bounded filters, wrapping the fixed, parameterized 'get_project_findings' query.
"""

from datetime import datetime, timezone
import time
from typing import Any
from pydantic import BaseModel, Field

from vulnify.agent.registry import ToolDefinition
from vulnify.agent.schemas import TraceFragment
from vulnify.graph.vulnerability_repository import get_vulnerability_repository


class ListFindingsInput(BaseModel):
    """Input parameters for listing project findings."""

    project_id: str = Field(..., description="Unique project identifier", min_length=1)
    service_id: str | None = Field(default=None, description="Optional service scope filter")
    priority: str | None = Field(default=None, description="Optional priority filter (Highest, High, Medium, Low)")
    status: str | None = Field(default=None, description="Optional triage status filter (open, affected, fixed, etc.)")
    search: str | None = Field(default=None, description="Optional search term matching package or advisory ID")
    page: int = Field(default=1, ge=1, description="1-indexed page number")
    page_size: int = Field(default=25, ge=1, le=100, description="Items per page (max 100)")


class FindingSummaryItem(BaseModel):
    """Normalized finding item returned in list view."""

    id: str
    project_id: str
    service_id: str
    service_name: str
    advisory_id: str
    advisory_summary: str
    package_name: str
    package_version: str
    severity: str
    priority: str
    status: str
    path_depth: int | None = None
    fixed_version: str | None = None
    review_required: bool = False
    review_reason: str | None = None


class ListFindingsResult(BaseModel):
    """Structured result returned by list_findings tool."""

    items: list[FindingSummaryItem]
    total: int
    page: int
    page_size: int
    trace: TraceFragment


async def handle_list_findings(inputs: ListFindingsInput) -> ListFindingsResult:
    """Execute parameterized get_project_findings query and construct trace fragment."""
    start = time.perf_counter()
    repo = get_vulnerability_repository()

    offset = (inputs.page - 1) * inputs.page_size
    items_raw, total = repo.get_project_findings(
        project_id=inputs.project_id,
        service_id=inputs.service_id,
        search=inputs.search,
        priority=inputs.priority,
        status=inputs.status,
        limit=inputs.page_size,
        offset=offset,
    )

    items = [
        FindingSummaryItem(
            id=f.get("id") or f"{f.get('service_id', '')}:{f.get('advisory_id', '')}:{f.get('package_version_id', '')}",
            project_id=inputs.project_id,
            service_id=f.get("service_id", ""),
            service_name=f.get("service_name", ""),
            advisory_id=f.get("advisory_id", ""),
            advisory_summary=f.get("advisory_summary", ""),
            package_name=f.get("package_name", ""),
            package_version=f.get("package_version", ""),
            severity=f.get("severity", "UNKNOWN"),
            priority=f.get("priority", "unknown"),
            status=f.get("status", "open"),
            path_depth=f.get("path_depth"),
            fixed_version=f.get("fixed_version"),
            review_required=bool(f.get("review_required", False)),
            review_reason=f.get("review_reason"),
        )
        for f in items_raw
    ]

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    now = int(datetime.now(timezone.utc).timestamp())

    summary = (
        f"Retrieved {len(items)} finding(s) (total: {total}) for project '{inputs.project_id}'."
        if items
        else f"No findings found for project '{inputs.project_id}' matching criteria."
    )

    trace = TraceFragment(
        tool_name="list_findings",
        query_id="get_project_findings",
        inputs=inputs.model_dump(),
        result_summary=summary,
        duration_ms=duration_ms,
        record_count=len(items),
        evaluated_at=now,
        outcome="success" if items else "empty",
        evidence_references=[item.advisory_id for item in items[:10]],
    )

    return ListFindingsResult(
        items=items,
        total=total,
        page=inputs.page,
        page_size=inputs.page_size,
        trace=trace,
    )


list_findings_tool = ToolDefinition(
    name="list_findings",
    description="Retrieve vulnerability findings for a project with bounded filtering and pagination.",
    classification="read_only",
    input_model=ListFindingsInput,
    output_model=ListFindingsResult,
    handler=handle_list_findings,
    query_id="get_project_findings",
    requires_approval=False,
)
