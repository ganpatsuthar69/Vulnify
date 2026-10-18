"""Tool: get_dependency_paths (US-601 AC-1 / AC-2).

Purpose:
Traverses the dependency graph to find bounded shortest paths from the service entrypoint
to the vulnerable package version, returning intermediate nodes, edges, provenance, and depth.
Wraps the parameterized 'get_project_finding_paths' query.
"""

from datetime import datetime, timezone
import time
from typing import Any
from pydantic import BaseModel, Field

from vulnify.agent.registry import ToolDefinition
from vulnify.agent.schemas import TraceFragment
from vulnify.graph.vulnerability_repository import get_vulnerability_repository


class GetDependencyPathsInput(BaseModel):
    """Input parameters for dependency path traversal."""

    project_id: str = Field(..., description="Unique project identifier", min_length=1)
    finding_id: str = Field(
        ...,
        description="Finding identifier (find-... hash) or advisory ID (e.g. GHSA-..., OSV-...)",
        min_length=1,
    )
    max_depth: int = Field(
        default=8,
        ge=1,
        le=15,
        description="Maximum dependency path traversal depth (bounded 1..15)",
    )
    limit: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum number of shortest paths to return (bounded 1..20)",
    )


class PathProvenance(BaseModel):
    """Provenance and import origin for dependency nodes."""

    source_filename: str | None = None
    content_hash: str | None = None
    imported_at: int | None = None
    classification: str = "manifest"
    origin: str = "stored_graph"


class PathNode(BaseModel):
    """A node in the dependency path (Service or PackageVersion)."""

    id: str
    node_type: str
    display_name: str
    package_name: str | None = None
    package_version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    is_target: bool = False
    is_entry_point: bool = False
    provenance: PathProvenance | None = None


class PathEdge(BaseModel):
    """A directed edge in the dependency path (e.g. CALLS, DEPENDS_ON)."""

    id: str
    source_id: str
    target_id: str
    relationship_type: str
    direct: bool = False
    origin: str = "manifest"


class DependencyPathItem(BaseModel):
    """A complete path from service root to vulnerable dependency."""

    id: str
    depth: int
    is_direct: bool
    nodes: list[PathNode]
    edges: list[PathEdge]
    summary_text: str


class GetDependencyPathsResult(BaseModel):
    """Result returned by get_dependency_paths tool."""

    has_path: bool
    paths: list[DependencyPathItem]
    total_found: int
    is_truncated: bool
    max_depth_evaluated: int
    service_id: str | None = None
    service_name: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    no_path_message: str | None = None
    trace: TraceFragment


async def handle_get_dependency_paths(inputs: GetDependencyPathsInput) -> GetDependencyPathsResult:
    """Traverse graph for dependency paths with honest no-path guarantees."""
    start = time.perf_counter()
    repo = get_vulnerability_repository()
    now = int(datetime.now(timezone.utc).timestamp())

    # 1. Resolve finding details to identify root service and target package version
    finding = repo.get_project_finding_detail(inputs.project_id, inputs.finding_id)
    if not finding:
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        trace = TraceFragment(
            tool_name="get_dependency_paths",
            query_id="get_project_finding_paths",
            inputs=inputs.model_dump(),
            result_summary=f"Finding '{inputs.finding_id}' not found in project '{inputs.project_id}'.",
            duration_ms=duration_ms,
            record_count=0,
            evaluated_at=now,
            outcome="empty",
            warning=f"Finding '{inputs.finding_id}' not found.",
        )
        return GetDependencyPathsResult(
            has_path=False,
            paths=[],
            total_found=0,
            is_truncated=False,
            max_depth_evaluated=inputs.max_depth,
            no_path_message=f"Finding '{inputs.finding_id}' was not found in project '{inputs.project_id}'.",
            trace=trace,
        )

    service_id = finding["service_id"]
    service_name = finding.get("service_name", service_id)
    package_version_id = finding["package_version_id"]
    package_name = finding.get("package_name", "")
    package_version = finding.get("package_version", "")
    advisory_id = finding.get("advisory_id", "")

    # 2. Query parameterized shortest paths
    raw_paths, is_truncated, total_found = repo.get_finding_dependency_paths(
        project_id=inputs.project_id,
        service_id=service_id,
        package_version_id=package_version_id,
        max_depth=inputs.max_depth,
        limit=inputs.limit,
    )

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    has_path = len(raw_paths) > 0

    paths: list[DependencyPathItem] = []
    for p in raw_paths:
        nodes = [
            PathNode(
                id=n["id"],
                node_type=n.get("node_type", "package"),
                display_name=n.get("display_name", n["id"]),
                package_name=n.get("package_name"),
                package_version=n.get("package_version"),
                ecosystem=n.get("ecosystem"),
                purl=n.get("purl"),
                is_target=n.get("is_target", False),
                is_entry_point=n.get("is_entry_point", False),
                provenance=PathProvenance(**n["provenance"]) if n.get("provenance") else None,
            )
            for n in p.get("nodes", [])
        ]
        edges = [
            PathEdge(
                id=e["id"],
                source_id=e["source_id"],
                target_id=e["target_id"],
                relationship_type=e.get("relationship_type", "DEPENDS_ON"),
                direct=e.get("direct", False),
                origin=e.get("origin", "manifest"),
            )
            for e in p.get("edges", [])
        ]
        paths.append(
            DependencyPathItem(
                id=p["id"],
                depth=p["depth"],
                is_direct=p.get("is_direct", False),
                nodes=nodes,
                edges=edges,
                summary_text=p.get("summary_text", ""),
            )
        )

    if not has_path:
        no_path_msg = (
            f"No dependency path found between service '{service_name}' and package '{package_name}@{package_version}' "
            f"within depth limit of {inputs.max_depth}."
        )
        trace = TraceFragment(
            tool_name="get_dependency_paths",
            query_id="get_project_finding_paths",
            inputs=inputs.model_dump(),
            result_summary=no_path_msg,
            duration_ms=duration_ms,
            record_count=0,
            evaluated_at=now,
            outcome="no_path",
            evidence_references=[advisory_id] if advisory_id else [],
            warning="Absence of a dependency path within this depth limit does not guarantee safety or absence of exposure.",
        )
        return GetDependencyPathsResult(
            has_path=False,
            paths=[],
            total_found=0,
            is_truncated=False,
            max_depth_evaluated=inputs.max_depth,
            service_id=service_id,
            service_name=service_name,
            package_name=package_name,
            package_version=package_version,
            no_path_message=no_path_msg,
            trace=trace,
        )

    shortest_depth = paths[0].depth if paths else 0
    direct_label = "direct" if shortest_depth == 1 else f"transitive (depth {shortest_depth})"
    summary = (
        f"Found {len(paths)} path(s) (total discovered: {total_found}) from service '{service_name}' to "
        f"{package_name}@{package_version} [{direct_label}]."
    )

    trace = TraceFragment(
        tool_name="get_dependency_paths",
        query_id="get_project_finding_paths",
        inputs=inputs.model_dump(),
        result_summary=summary,
        duration_ms=duration_ms,
        record_count=len(paths),
        evaluated_at=now,
        outcome="success",
        evidence_references=[advisory_id] if advisory_id else [],
    )

    return GetDependencyPathsResult(
        has_path=True,
        paths=paths,
        total_found=total_found,
        is_truncated=is_truncated,
        max_depth_evaluated=inputs.max_depth,
        service_id=service_id,
        service_name=service_name,
        package_name=package_name,
        package_version=package_version,
        no_path_message=None,
        trace=trace,
    )


get_dependency_paths_tool = ToolDefinition(
    name="get_dependency_paths",
    description="Traverse the dependency graph to find bounded shortest paths from service root to vulnerable package version.",
    classification="read_only",
    input_model=GetDependencyPathsInput,
    output_model=GetDependencyPathsResult,
    handler=handle_get_dependency_paths,
    query_id="get_project_finding_paths",
    requires_approval=False,
)
