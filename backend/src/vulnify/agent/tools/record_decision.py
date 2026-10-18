"""Tool: record_decision (US-601 AC-1 / AC-2 / AC-3).

Purpose:
Gated write tool that records an explicit human-approved triage decision (e.g. open, affected,
not_affected, fixed) on a vulnerability finding.
Requires explicit confirmation ('confirmed': true) and enforces justification rules.
Wraps the parameterized 'record_triage_decision' Cypher query.
"""

from datetime import datetime, timezone
import time
from typing import Literal
from fastapi import HTTPException
from pydantic import BaseModel, Field, model_validator

from vulnify.agent.registry import ToolDefinition
from vulnify.agent.schemas import TraceFragment
from vulnify.graph.vulnerability_repository import get_vulnerability_repository


class RecordDecisionInput(BaseModel):
    """Input parameters for recording a triage decision."""

    project_id: str = Field(..., description="Unique project identifier", min_length=1)
    finding_id: str = Field(
        ...,
        description="Finding identifier (find-... hash) or advisory ID (e.g. GHSA-..., OSV-...)",
        min_length=1,
    )
    status: Literal["open", "affected", "not_affected", "fixed"] = Field(
        ...,
        description="Target triage status ('open', 'affected', 'not_affected', 'fixed')",
    )
    justification: str | None = Field(
        default=None,
        description="Explanation for the decision; mandatory (>=10 chars) when marking 'not_affected'",
    )
    triaged_by: str | None = Field(
        default="agent",
        description="Identity of the operator or agent recording the decision",
    )
    confirmed: bool = Field(
        default=False,
        description="Explicit human approval confirmation (required to mutate database)",
    )

    @model_validator(mode="after")
    def validate_justification_for_not_affected(self) -> "RecordDecisionInput":
        if self.status == "not_affected":
            if not self.justification or len(self.justification.strip()) < 10:
                raise ValueError(
                    "A clear justification of at least 10 characters is required when marking a finding as 'not_affected'."
                )
        return self


class RecordDecisionResult(BaseModel):
    """Result returned by record_decision tool."""

    success: bool
    project_id: str
    finding_id: str
    advisory_id: str
    package_version_id: str
    previous_status: str
    new_status: str
    justification: str | None = None
    triaged_by: str
    updated_at: int
    trace: TraceFragment


async def handle_record_decision(inputs: RecordDecisionInput) -> RecordDecisionResult:
    """Record verified triage decision in graph database after human approval gating."""
    start = time.perf_counter()
    repo = get_vulnerability_repository()
    now = int(datetime.now(timezone.utc).timestamp())

    # 1. Enforce confirmation defense-in-depth
    if not inputs.confirmed:
        raise HTTPException(
            status_code=403,
            detail="Operation rejected: 'record_decision' is a gated write tool requiring explicit approval ('confirmed': true).",
        )

    from vulnify.services.decision_service import get_decision_service

    # 2. Resolve finding to locate specific advisory and package_version_id
    finding = repo.get_project_finding_detail(inputs.project_id, inputs.finding_id)
    if not finding:
        raise HTTPException(
            status_code=404,
            detail=f"Finding '{inputs.finding_id}' not found in project '{inputs.project_id}'.",
        )

    advisory_id = finding["advisory_id"]
    package_version_id = finding["package_version_id"]
    previous_status = finding.get("status", "open")

    # 3. Persist decision and baseline using centralized decision service
    decision_service = get_decision_service(repo)
    dec_record = decision_service.record_decision(
        project_id=inputs.project_id,
        finding_id=inputs.finding_id,
        status=inputs.status,
        justification=inputs.justification,
        triaged_by=inputs.triaged_by or "agent",
    )
    updated = True

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    summary = (
        f"Recorded triage decision for finding '{inputs.finding_id}' ({advisory_id}): "
        f"status updated from '{previous_status}' to '{inputs.status}'. "
        f"Triaged by: {inputs.triaged_by or 'agent'}."
    )

    trace = TraceFragment(
        tool_name="record_decision",
        query_id="record_triage_decision",
        inputs=inputs.model_dump(),
        result_summary=summary,
        duration_ms=duration_ms,
        record_count=1 if updated else 0,
        evaluated_at=now,
        outcome="success" if updated else "error",
        evidence_references=[advisory_id],
    )

    return RecordDecisionResult(
        success=bool(updated),
        project_id=inputs.project_id,
        finding_id=inputs.finding_id,
        advisory_id=advisory_id,
        package_version_id=package_version_id,
        previous_status=previous_status,
        new_status=inputs.status,
        justification=inputs.justification,
        triaged_by=inputs.triaged_by or "agent",
        updated_at=now,
        trace=trace,
    )


record_decision_tool = ToolDefinition(
    name="record_decision",
    description="Gated write tool that records an explicit human-approved triage decision (open, affected, not_affected, fixed).",
    classification="write_gated",
    input_model=RecordDecisionInput,
    output_model=RecordDecisionResult,
    handler=handle_record_decision,
    query_id="record_triage_decision",
    requires_approval=True,
)
