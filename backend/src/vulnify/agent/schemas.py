"""Pydantic schemas and contracts for Vulnify Agent Tools and MCP Registry (US-601).

Core Contracts:
1. TraceFragment: execution provenance, query identifier, duration, and result summary.
2. ToolClassification: explicit distinction between read-only and gated-write tools.
3. ToolMetadata & ToolListResponse: dynamic discovery payloads without leaking sensitive internals.
4. ToolExecutionRequest & ToolExecutionResponse: typed inputs and outputs with error categorization.
"""

from typing import Any, Literal
from pydantic import BaseModel, Field

ToolClassification = Literal["read_only", "write_gated"]


class TraceFragment(BaseModel):
    """Execution provenance and telemetry for an agent tool call."""

    tool_name: str = Field(..., description="Stable identifier of the executed tool")
    tool_version: str = Field(default="1.0.0", description="Semantic version of the tool contract")
    query_id: str | None = Field(
        default=None,
        description="Cypher query catalog identifier or service operation name",
    )
    inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Safe, bounded input arguments passed to the tool",
    )
    result_summary: str = Field(
        ...,
        description="Human-readable summary of query results or actions taken",
    )
    duration_ms: float = Field(
        ...,
        ge=0.0,
        description="Execution duration in milliseconds",
    )
    record_count: int | None = Field(
        default=None,
        ge=0,
        description="Number of records returned from the query, if applicable",
    )
    evaluated_at: int = Field(
        ...,
        description="Unix timestamp when tool execution finished",
    )
    outcome: Literal["success", "no_path", "empty", "rejected", "error"] = Field(
        default="success",
        description="Standardized outcome classification",
    )
    evidence_references: list[str] = Field(
        default_factory=list,
        description="List of primary entity IDs or advisory references returned",
    )
    warning: str | None = Field(
        default=None,
        description="Optional honest warning or data-quality caveat",
    )


class ToolMetadata(BaseModel):
    """Dynamic tool definition exposed to frontend and MCP discovery."""

    name: str = Field(..., description="Unique tool identifier (e.g. list_findings)")
    description: str = Field(..., description="Clear explanation of the tool's purpose and output")
    classification: ToolClassification = Field(
        ...,
        description="'read_only' for queries or 'write_gated' for state changes",
    )
    query_id: str | None = Field(
        default=None,
        description="Corresponding query in docs/cypher-catalog.md if graph-backed",
    )
    requires_approval: bool = Field(
        default=False,
        description="Whether tool requires explicit human approval gating to execute",
    )
    input_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema of the tool's input parameters",
    )


class ToolListResponse(BaseModel):
    """List of all dynamically registered agent tools."""

    tools: list[ToolMetadata]
    total: int


class ToolExecutionRequest(BaseModel):
    """Generic tool invocation payload for HTTP execution."""

    tool_name: str = Field(..., description="Target tool name to execute")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Tool-specific input arguments")


class ToolExecutionResponse(BaseModel):
    """Unified tool execution response with structured data and trace fragment."""

    tool_name: str
    status: Literal["success", "error", "rejected"]
    data: Any = Field(default=None, description="Typed output data returned by the tool handler")
    trace: TraceFragment
    error_message: str | None = Field(default=None, description="Safe error message if execution failed")


# =====================================================================
# US-602: Streaming Agent Request & Event Schemas
# =====================================================================

AgentRunState = Literal[
    "accepted",
    "running",
    "completed",
    "cancelled",
    "failed",
    "timeout",
    "step_limit_reached",
]


class AgentChatRequest(BaseModel):
    """Client request initiating a natural-language agent investigation."""

    project_id: str = Field(..., description="Active project context identifier", min_length=1)
    message: str = Field(
        ...,
        description="User question or investigation instruction",
        min_length=1,
        max_length=2000,
    )
    run_id: str | None = Field(default=None, description="Optional client-provided or correlation run ID")


class AgentStreamEvent(BaseModel):
    """Envelope for all Server-Sent Events emitted by the agent orchestrator."""

    event: str = Field(..., description="Event type name (e.g. run_started, tool_started, answer_delta)")
    run_id: str = Field(..., description="Unique run identifier")
    sequence: int = Field(..., ge=1, description="Strictly increasing event sequence number")
    timestamp: int = Field(..., description="Unix timestamp of event generation")
    data: dict[str, Any] = Field(default_factory=dict, description="Typed event payload")

    def to_sse(self) -> str:
        """Format as SSE data line."""
        return f"event: {self.event}\ndata: {self.model_dump_json()}\n\n"


class AgentRunCancelResponse(BaseModel):
    """Response returned when an agent run cancellation is acknowledged."""

    run_id: str
    status: Literal["cancelling", "cancelled", "already_terminal", "not_found"]
    message: str


class AgentRunStatusResponse(BaseModel):
    """Current execution status of an agent run."""

    run_id: str
    project_id: str
    status: AgentRunState
    step_count: int
    created_at: int
    completed_at: int | None = None
    error_message: str | None = None


# =====================================================================
# US-603: Stored Traces and Investigation Run Schemas
# =====================================================================


class AgentRunSummary(BaseModel):
    """Summary representation of a stored agent investigation session for listings."""

    id: str
    project_id: str
    user_email: str
    prompt: str
    status: AgentRunState
    started_at: int
    completed_at: int | None = None
    has_final_answer: bool
    step_count: int
    tool_call_count: int
    error_message: str | None = None


class AgentRunDetail(BaseModel):
    """Full detail of a stored agent run including generated answer and referenced entities."""

    id: str
    project_id: str
    user_id: str
    user_email: str
    prompt: str
    status: AgentRunState
    started_at: int
    completed_at: int | None = None
    final_answer: str | None = None
    error_message: str | None = None
    step_count: int
    findings_referenced: list[str] = Field(default_factory=list)
    paths_referenced: list[str] = Field(default_factory=list)
    tool_call_count: int


class AgentToolCallDetail(BaseModel):
    """Durable record of a single tool execution with inputs and trace fragment."""

    id: str
    run_id: str
    sequence: int
    tool_name: str
    display_name: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)
    result_summary: str
    status: Literal["running", "success", "error", "rejected"]
    query_id: str | None = None
    duration_ms: float | None = None
    outcome: str | None = None
    evidence_references: list[str] = Field(default_factory=list)
    started_at: int
    completed_at: int | None = None
    error_message: str | None = None


class AgentRunTraceResponse(BaseModel):
    """Complete trace payload with run metadata and ordered tool call timeline."""

    run: AgentRunDetail
    tool_calls: list[AgentToolCallDetail]


class AgentRunListResponse(BaseModel):
    """Paginated listing of past agent runs for a project."""

    items: list[AgentRunSummary]
    total: int
    page: int
    page_size: int

