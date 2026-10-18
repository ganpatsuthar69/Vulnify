"""Tool: explain_finding (US-601 AC-1 / AC-2).

Purpose:
Synthesizes graph exposure evidence, reachability depth, advisory details, and remediation status
into an objective architectural summary, adhering strictly to Vulnify's non-exploitability safety rules.
"""

from datetime import datetime, timezone
import time
from typing import Any
from pydantic import BaseModel, Field

from vulnify.agent.registry import ToolDefinition
from vulnify.agent.schemas import TraceFragment
from vulnify.graph.vulnerability_repository import get_vulnerability_repository


class ExplainFindingInput(BaseModel):
    """Input parameters for finding explanation."""

    project_id: str = Field(..., description="Unique project identifier", min_length=1)
    finding_id: str = Field(
        ...,
        description="Finding identifier (find-... hash) or advisory ID (e.g. GHSA-..., OSV-...)",
        min_length=1,
    )


class ExposureExplanation(BaseModel):
    """Structured architectural exposure breakdown."""

    service_name: str
    package_name: str
    package_version: str
    exposure_type: str  # "direct", "transitive", "no_path_found"
    path_depth: int | None = None
    dependency_chain_summary: str
    advisory_id: str
    severity: str
    priority: str
    priority_reasons: list[str] = Field(default_factory=list)
    remediation_status: str
    fixed_version: str | None = None
    non_exploitability_disclaimer: str


class ExplainFindingResult(BaseModel):
    """Result returned by explain_finding tool."""

    found: bool
    explanation: ExposureExplanation | None = None
    summary_text: str
    trace: TraceFragment


async def handle_explain_finding(inputs: ExplainFindingInput) -> ExplainFindingResult:
    """Produce deterministic, evidence-backed architectural explanation for finding."""
    start = time.perf_counter()
    repo = get_vulnerability_repository()
    now = int(datetime.now(timezone.utc).timestamp())

    finding = repo.get_project_finding_detail(inputs.project_id, inputs.finding_id)
    if not finding:
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        trace = TraceFragment(
            tool_name="explain_finding",
            query_id="explain_finding_synthesis",
            inputs=inputs.model_dump(),
            result_summary=f"Finding '{inputs.finding_id}' not found in project '{inputs.project_id}'.",
            duration_ms=duration_ms,
            record_count=0,
            evaluated_at=now,
            outcome="empty",
            warning=f"Finding '{inputs.finding_id}' not found.",
        )
        return ExplainFindingResult(
            found=False,
            explanation=None,
            summary_text=f"Finding '{inputs.finding_id}' was not found in project '{inputs.project_id}'.",
            trace=trace,
        )

    service_id = finding["service_id"]
    service_name = finding.get("service_name", service_id)
    package_version_id = finding["package_version_id"]
    package_name = finding.get("package_name", "")
    package_version = finding.get("package_version", "")
    advisory_id = finding.get("advisory_id", "")
    severity = finding.get("severity", "UNKNOWN")
    priority = finding.get("priority", "unknown")
    priority_reasons = finding.get("priority_reasons", [])
    fixed_version = finding.get("fixed_version")

    # Fetch shortest path for evidence
    raw_paths, _, _ = repo.get_finding_dependency_paths(
        project_id=inputs.project_id,
        service_id=service_id,
        package_version_id=package_version_id,
        max_depth=8,
        limit=1,
    )

    has_path = len(raw_paths) > 0
    shortest_path = raw_paths[0] if has_path else None
    path_depth = shortest_path["depth"] if shortest_path else None

    if shortest_path and path_depth == 1:
        exposure_type = "direct"
        chain_summary = shortest_path.get("summary_text", f"{service_name} → {package_name}@{package_version}")
        exposure_desc = f"Direct dependency exposure: Service '{service_name}' directly declares and imports '{package_name}@{package_version}'."
    elif shortest_path and path_depth and path_depth > 1:
        exposure_type = "transitive"
        chain_summary = shortest_path.get("summary_text", f"{service_name} → ... → {package_name}@{package_version}")
        exposure_desc = f"Transitive dependency exposure: Service '{service_name}' reaches '{package_name}@{package_version}' across {path_depth} dependency hops."
    else:
        exposure_type = "no_path_found"
        chain_summary = "No reachable path discovered from service within depth limit of 8."
        exposure_desc = f"No dependency path discovered between service '{service_name}' and '{package_name}@{package_version}' within 8 hops."

    if fixed_version:
        remediation_status = f"Remediation available: Upgrade package '{package_name}' to version {fixed_version}."
    else:
        remediation_status = "No official fixed version recorded in advisory metadata. Monitor upstream package maintainers for security patch release."

    disclaimer = (
        "Vulnify reports architectural exposure based on static dependency graphs and service manifests, "
        "not proof of runtime exploitability. Absence of a path does not guarantee safety."
    )

    reasons_formatted = "; ".join(priority_reasons) if priority_reasons else "standard priority rules"

    summary_text = (
        f"Finding {advisory_id} on {package_name}@{package_version} is ranked as '{priority}' priority "
        f"based on: {reasons_formatted}. "
        f"{exposure_desc} "
        f"{remediation_status} "
        f"{disclaimer}"
    )

    explanation = ExposureExplanation(
        service_name=service_name,
        package_name=package_name,
        package_version=package_version,
        exposure_type=exposure_type,
        path_depth=path_depth,
        dependency_chain_summary=chain_summary,
        advisory_id=advisory_id,
        severity=severity,
        priority=priority,
        priority_reasons=priority_reasons,
        remediation_status=remediation_status,
        fixed_version=fixed_version,
        non_exploitability_disclaimer=disclaimer,
    )

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    trace = TraceFragment(
        tool_name="explain_finding",
        query_id="explain_finding_synthesis",
        inputs=inputs.model_dump(),
        result_summary=f"Synthesized explanation for {advisory_id} ({exposure_type} exposure, priority={priority}).",
        duration_ms=duration_ms,
        record_count=1,
        evaluated_at=now,
        outcome="success",
        evidence_references=[advisory_id],
        warning="Exposure indicates architectural reachability, not proof of runtime exploitability.",
    )

    return ExplainFindingResult(
        found=True,
        explanation=explanation,
        summary_text=summary_text,
        trace=trace,
    )


explain_finding_tool = ToolDefinition(
    name="explain_finding",
    description="Synthesizes graph exposure, reachability depth, advisory details, and remediation into an objective summary.",
    classification="read_only",
    input_model=ExplainFindingInput,
    output_model=ExplainFindingResult,
    handler=handle_explain_finding,
    query_id="explain_finding_synthesis",
    requires_approval=False,
)
