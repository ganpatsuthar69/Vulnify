"""Agent Tools and Capability Discovery Router (US-601 / US-602).

Responsibilities:
1. Dynamic tool discovery via GET /api/agent/tools.
2. Controlled execution via POST /api/agent/tools/{tool_name}/execute.
3. Server-Sent Events (SSE) streaming chat via POST /api/agent/chat/stream (US-602).
4. Run cancellation via POST /api/agent/runs/{run_id}/cancel (US-602).
5. Enforces admin-only authentication, project scoping, and audit logging.
"""

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse

from vulnify.agent.executor import ToolExecutor
from vulnify.agent.orchestrator import AgentOrchestrator, get_agent_orchestrator
from vulnify.agent.registry import ToolRegistry, get_tool_registry
from vulnify.agent.schemas import (
    AgentChatRequest,
    AgentRunCancelResponse,
    AgentRunDetail,
    AgentRunListResponse,
    AgentRunState,
    AgentRunStatusResponse,
    AgentRunSummary,
    AgentRunTraceResponse,
    AgentToolCallDetail,
    ToolExecutionResponse,
    ToolListResponse,
    ToolMetadata,
)
from vulnify.dependencies import require_auth
from vulnify.graph.agent_run_repository import IAgentRunRepository, get_agent_run_repository
from vulnify.graph.project_repository import IProjectRepository, get_project_repository
from vulnify.schemas import UserResponse

router = APIRouter(
    prefix="/api/agent",
    tags=["Agent Tools & Investigation"],
)


@router.get(
    "/tools",
    response_model=ToolListResponse,
    status_code=status.HTTP_200_OK,
    summary="List available agent tools and dynamic schemas (US-601)",
)
async def list_agent_tools(
    current_user: UserResponse = Depends(require_auth),
    registry: ToolRegistry = Depends(get_tool_registry),
) -> ToolListResponse:
    """Return all dynamically registered agent tools, their schemas, and approval requirements."""
    return registry.get_metadata()


@router.get(
    "/tools/{tool_name}",
    response_model=ToolMetadata,
    status_code=status.HTTP_200_OK,
    summary="Get single tool specification by name (US-601)",
)
async def get_tool_definition(
    tool_name: str,
    current_user: UserResponse = Depends(require_auth),
    registry: ToolRegistry = Depends(get_tool_registry),
) -> ToolMetadata:
    """Retrieve metadata and parameter schema for a specific registered tool."""
    tool = registry.get(tool_name)
    if not tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent tool '{tool_name}' not found.",
        )
    return tool.get_metadata()


@router.post(
    "/tools/{tool_name}/execute",
    response_model=ToolExecutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute registered agent tool with validation and trace logging (US-601)",
)
async def execute_agent_tool(
    tool_name: str,
    arguments: dict[str, Any],
    current_user: UserResponse = Depends(require_auth),
    registry: ToolRegistry = Depends(get_tool_registry),
) -> ToolExecutionResponse:
    """Execute a registered agent tool.

    Validates arguments against the registered Pydantic input schema.
    Gated write tools require explicit human approval ('confirmed': true).
    Returns execution data along with a complete TraceFragment.
    """
    executor = ToolExecutor(registry=registry)
    is_admin = getattr(current_user, "role", "") == "admin"
    actor_email = getattr(current_user, "email", str(current_user.id))

    response = await executor.execute(
        tool_name=tool_name,
        arguments=arguments,
        actor_email=actor_email,
        is_admin=is_admin,
    )

    return response


# =====================================================================
# US-602: Streaming Agent Investigation Chat & Run Management
# =====================================================================


@router.post(
    "/chat/stream",
    response_class=StreamingResponse,
    status_code=status.HTTP_200_OK,
    summary="Stream agent investigation over Server-Sent Events (US-602)",
)
async def stream_agent_investigation(
    request: AgentChatRequest,
    current_user: UserResponse = Depends(require_auth),
    orchestrator: AgentOrchestrator = Depends(get_agent_orchestrator),
    project_repo: IProjectRepository = Depends(get_project_repository),
) -> StreamingResponse:
    """Stream tool steps and the final grounded answer over Server-Sent Events.

    Acceptance criteria enforced:
    1. Admin-only authentication required.
    2. Active project existence validated.
    3. Streams tool_started, tool_completed, and answer_delta incrementally.
    4. Answers cite real finding IDs and dependency paths.
    """
    # AC-3: Only a signed-in admin can use the agent endpoint
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only signed-in administrators can use the agent investigation chat.",
        )

    # Validate message content
    if not request.message or not request.message.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Message cannot be empty or whitespace only.",
        )

    if len(request.message) > 2000:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Message length exceeds maximum limit of 2,000 characters.",
        )

    # Validate project context
    project = project_repo.get_by_id(request.project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{request.project_id}' not found.",
        )

    stream_generator = orchestrator.stream_investigation(
        project_id=request.project_id,
        message=request.message,
        user_id=str(current_user.id),
        user_email=current_user.email,
        run_id=request.run_id,
    )

    return StreamingResponse(
        stream_generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post(
    "/runs/{run_id}/cancel",
    response_model=AgentRunCancelResponse,
    status_code=status.HTTP_200_OK,
    summary="Cancel active agent investigation run (US-602 AC-1)",
)
async def cancel_agent_run(
    run_id: str,
    current_user: UserResponse = Depends(require_auth),
    orchestrator: AgentOrchestrator = Depends(get_agent_orchestrator),
) -> AgentRunCancelResponse:
    """Signal immediate cancellation to an active agent run.

    Idempotent; verifies run ownership and stops further tool scheduling.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only administrators can cancel agent runs.",
        )

    return await orchestrator.cancel_run(run_id=run_id, user_id=str(current_user.id))


@router.get(
    "/runs/{run_id}/status",
    response_model=AgentRunStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get execution status of an agent run (US-602)",
)
async def get_agent_run_status(
    run_id: str,
    current_user: UserResponse = Depends(require_auth),
    orchestrator: AgentOrchestrator = Depends(get_agent_orchestrator),
) -> AgentRunStatusResponse:
    """Retrieve status and step telemetry for a specific agent run."""
    run = orchestrator.get_run(run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent run '{run_id}' not found.",
        )

    if run.user_id != str(current_user.id) and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent run '{run_id}' not found.",
        )

    return AgentRunStatusResponse(
        run_id=run.run_id,
        project_id=run.project_id,
        status=run.status,
        step_count=run.step_count,
        created_at=run.created_at,
        completed_at=run.completed_at,
        error_message=run.error_message,
    )


# =====================================================================
# US-603: Stored Traces and Investigation Run Management Endpoints
# =====================================================================


@router.get(
    "/runs",
    response_model=AgentRunListResponse,
    status_code=status.HTTP_200_OK,
    summary="List stored agent investigation runs for a project (US-603)",
)
async def list_agent_runs(
    project_id: str = Query(..., description="Project ID to scope runs", min_length=1),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
    current_user: UserResponse = Depends(require_auth),
    project_repo: IProjectRepository = Depends(get_project_repository),
    agent_run_repo: IAgentRunRepository = Depends(get_agent_run_repository),
) -> AgentRunListResponse:
    """Retrieve historical agent runs for a project with pagination.

    Enforces admin-only authorization and project-scoping.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only administrators can view investigation run history.",
        )

    project = project_repo.get_by_id(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{project_id}' not found.",
        )

    offset = (page - 1) * page_size
    runs, total = agent_run_repo.list_runs(project_id=project_id, limit=page_size, offset=offset)

    items = [
        AgentRunSummary(
            id=r.id,
            project_id=r.project_id,
            user_email=r.user_email,
            prompt=r.prompt,
            status=r.status,  # type: ignore
            started_at=r.started_at,
            completed_at=r.completed_at,
            has_final_answer=bool(r.final_answer),
            step_count=r.step_count,
            tool_call_count=r.tool_call_count,
            error_message=r.error_message,
        )
        for r in runs
    ]

    return AgentRunListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/runs/by-finding/{finding_id}",
    response_model=list[AgentRunSummary],
    status_code=status.HTTP_200_OK,
    summary="Find stored agent runs referencing a finding (US-603)",
)
async def get_agent_runs_by_finding(
    finding_id: str,
    project_id: str = Query(..., description="Project ID context", min_length=1),
    limit: int = Query(10, ge=1, le=50, description="Max runs to return"),
    current_user: UserResponse = Depends(require_auth),
    project_repo: IProjectRepository = Depends(get_project_repository),
    agent_run_repo: IAgentRunRepository = Depends(get_agent_run_repository),
) -> list[AgentRunSummary]:
    """Find agent runs that investigated or referenced a specific finding ID."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only administrators can query finding investigation traces.",
        )

    project = project_repo.get_by_id(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{project_id}' not found.",
        )

    runs = agent_run_repo.get_runs_by_finding(
        project_id=project_id,
        finding_id=finding_id,
        limit=limit,
    )

    return [
        AgentRunSummary(
            id=r.id,
            project_id=r.project_id,
            user_email=r.user_email,
            prompt=r.prompt,
            status=r.status,  # type: ignore
            started_at=r.started_at,
            completed_at=r.completed_at,
            has_final_answer=bool(r.final_answer),
            step_count=r.step_count,
            tool_call_count=r.tool_call_count,
            error_message=r.error_message,
        )
        for r in runs
    ]


@router.get(
    "/runs/{run_id}",
    response_model=AgentRunDetail,
    status_code=status.HTTP_200_OK,
    summary="Retrieve single stored agent run by ID (US-603)",
)
async def get_agent_run(
    run_id: str,
    current_user: UserResponse = Depends(require_auth),
    orchestrator: AgentOrchestrator = Depends(get_agent_orchestrator),
    agent_run_repo: IAgentRunRepository = Depends(get_agent_run_repository),
) -> AgentRunDetail:
    """Retrieve full details of a stored agent run."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only administrators can inspect agent runs.",
        )

    # 1. Check in active orchestrator runs
    active_run = orchestrator.get_run(run_id)
    if active_run:
        return AgentRunDetail(
            id=active_run.run_id,
            project_id=active_run.project_id,
            user_id=active_run.user_id,
            user_email=active_run.user_email,
            prompt=active_run.prompt,
            status=active_run.status,
            started_at=active_run.created_at,
            completed_at=active_run.completed_at,
            final_answer=active_run.final_answer,
            error_message=active_run.error_message,
            step_count=active_run.step_count,
            findings_referenced=sorted(list(active_run.findings_referenced)),
            paths_referenced=active_run.paths_referenced,
            tool_call_count=len(active_run.tool_calls),
        )

    # 2. Check in durable repository
    run_rec = agent_run_repo.get_run_by_id(run_id)
    if run_rec:
        return AgentRunDetail(
            id=run_rec.id,
            project_id=run_rec.project_id,
            user_id=run_rec.user_id,
            user_email=run_rec.user_email,
            prompt=run_rec.prompt,
            status=run_rec.status,  # type: ignore
            started_at=run_rec.started_at,
            completed_at=run_rec.completed_at,
            final_answer=run_rec.final_answer,
            error_message=run_rec.error_message,
            step_count=run_rec.step_count,
            findings_referenced=run_rec.findings_referenced,
            paths_referenced=run_rec.paths_referenced,
            tool_call_count=run_rec.tool_call_count,
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Agent run '{run_id}' not found.",
    )


@router.get(
    "/runs/{run_id}/trace",
    response_model=AgentRunTraceResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve complete trace with ordered tool calls for a run (US-603)",
)
async def get_agent_run_trace(
    run_id: str,
    current_user: UserResponse = Depends(require_auth),
    orchestrator: AgentOrchestrator = Depends(get_agent_orchestrator),
    agent_run_repo: IAgentRunRepository = Depends(get_agent_run_repository),
) -> AgentRunTraceResponse:
    """Retrieve full execution trace with all tool calls in chronological order."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only administrators can inspect agent run traces.",
        )

    run_detail: AgentRunDetail | None = None
    active_run = orchestrator.get_run(run_id)
    if active_run:
        run_detail = AgentRunDetail(
            id=active_run.run_id,
            project_id=active_run.project_id,
            user_id=active_run.user_id,
            user_email=active_run.user_email,
            prompt=active_run.prompt,
            status=active_run.status,
            started_at=active_run.created_at,
            completed_at=active_run.completed_at,
            final_answer=active_run.final_answer,
            error_message=active_run.error_message,
            step_count=active_run.step_count,
            findings_referenced=sorted(list(active_run.findings_referenced)),
            paths_referenced=active_run.paths_referenced,
            tool_call_count=len(active_run.tool_calls),
        )
    else:
        run_rec = agent_run_repo.get_run_by_id(run_id)
        if run_rec:
            run_detail = AgentRunDetail(
                id=run_rec.id,
                project_id=run_rec.project_id,
                user_id=run_rec.user_id,
                user_email=run_rec.user_email,
                prompt=run_rec.prompt,
                status=run_rec.status,  # type: ignore
                started_at=run_rec.started_at,
                completed_at=run_rec.completed_at,
                final_answer=run_rec.final_answer,
                error_message=run_rec.error_message,
                step_count=run_rec.step_count,
                findings_referenced=run_rec.findings_referenced,
                paths_referenced=run_rec.paths_referenced,
                tool_call_count=run_rec.tool_call_count,
            )

    if not run_detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent run '{run_id}' not found.",
        )

    tool_calls = agent_run_repo.get_run_tool_calls(run_id)
    tool_call_details = [
        AgentToolCallDetail(
            id=tc.id,
            run_id=tc.run_id,
            sequence=tc.sequence,
            tool_name=tc.tool_name,
            display_name=tc.display_name,
            inputs=tc.inputs,
            result_summary=tc.result_summary,
            status=tc.status,  # type: ignore
            query_id=tc.query_id,
            duration_ms=tc.duration_ms,
            outcome=tc.outcome,
            evidence_references=tc.evidence_references,
            started_at=tc.started_at,
            completed_at=tc.completed_at,
            error_message=tc.error_message,
        )
        for tc in tool_calls
    ]

    return AgentRunTraceResponse(
        run=run_detail,
        tool_calls=tool_call_details,
    )

