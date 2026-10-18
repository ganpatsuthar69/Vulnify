"""Controlled Tool Execution Layer for Vulnify Agent (US-601).

Responsibilities:
1. Validates inputs against registered Pydantic input models.
2. Enforces explicit authorization and approval gating before invoking write tools.
3. Invokes fixed backend service handlers with parameterized arguments.
4. Captures execution duration, evidence references, and structured trace fragments.
5. Standardizes error responses into safe, categorized outputs without leaking internals.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any
from fastapi import HTTPException
from pydantic import ValidationError

from vulnify.agent.registry import ToolRegistry, get_tool_registry
from vulnify.agent.schemas import ToolExecutionResponse, TraceFragment
from vulnify.logging import get_request_id

logger = logging.getLogger("vulnify")


class ToolExecutor:
    """Orchestrates safe validation and invocation of registered agent tools."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or get_tool_registry()

    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        actor_email: str | None = None,
        is_admin: bool = False,
    ) -> ToolExecutionResponse:
        """Execute a registered tool given its name and argument dictionary."""
        start_time = time.perf_counter()
        now = int(datetime.now(timezone.utc).timestamp())
        req_id = get_request_id()

        # 1. Resolve tool from registry
        tool = self.registry.get(tool_name)
        if not tool:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            trace = TraceFragment(
                tool_name=tool_name,
                inputs=arguments,
                result_summary=f"Tool '{tool_name}' not found in registry.",
                duration_ms=duration_ms,
                evaluated_at=now,
                outcome="error",
                warning=f"Unknown tool: '{tool_name}'. Available tools can be queried via discovery.",
            )
            return ToolExecutionResponse(
                tool_name=tool_name,
                status="error",
                data=None,
                trace=trace,
                error_message=f"Unknown tool '{tool_name}'.",
            )

        # 2. Validate input schema
        try:
            validated_inputs = tool.input_model.model_validate(arguments)
        except ValidationError as val_err:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            err_msg = "; ".join(f"{e['loc']}: {e['msg']}" for e in val_err.errors())
            trace = TraceFragment(
                tool_name=tool.name,
                query_id=tool.query_id,
                inputs=arguments,
                result_summary=f"Input validation failed for '{tool.name}': {err_msg}",
                duration_ms=duration_ms,
                evaluated_at=now,
                outcome="error",
                warning="Tool argument validation error.",
            )
            return ToolExecutionResponse(
                tool_name=tool.name,
                status="error",
                data=None,
                trace=trace,
                error_message=f"Invalid arguments for tool '{tool.name}': {err_msg}",
            )

        # 3. Enforce Human Approval Gating on Write Tools (US-601 AC-2)
        if tool.classification == "write_gated":
            is_confirmed = getattr(validated_inputs, "confirmed", False)
            if not is_confirmed:
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                trace = TraceFragment(
                    tool_name=tool.name,
                    query_id=tool.query_id,
                    inputs=arguments,
                    result_summary=f"Execution rejected for '{tool.name}': explicit human approval is required ('confirmed': true).",
                    duration_ms=duration_ms,
                    evaluated_at=now,
                    outcome="rejected",
                    warning="Gated write tool blocked without human confirmation.",
                )
                return ToolExecutionResponse(
                    tool_name=tool.name,
                    status="rejected",
                    data=None,
                    trace=trace,
                    error_message=f"Tool '{tool.name}' is a write-capable tool and explicit human approval is required ('confirmed': true).",
                )

        # 4. Invoke the tool handler
        try:
            result = await tool.handler(validated_inputs)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Ensure result includes trace fragment
            trace = getattr(result, "trace", None)
            if not isinstance(trace, TraceFragment):
                trace = TraceFragment(
                    tool_name=tool.name,
                    query_id=tool.query_id,
                    inputs=arguments,
                    result_summary=f"Executed {tool.name} successfully.",
                    duration_ms=duration_ms,
                    evaluated_at=now,
                    outcome="success",
                )
            else:
                # Update duration if measured by executor
                trace.duration_ms = duration_ms

            logger.info(
                "Tool '%s' executed successfully in %.2fms",
                tool.name,
                duration_ms,
                extra={"request_id": req_id, "tool_name": tool.name, "actor": actor_email},
            )

            return ToolExecutionResponse(
                tool_name=tool.name,
                status="success",
                data=result,
                trace=trace,
            )

        except HTTPException as http_exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            trace = TraceFragment(
                tool_name=tool.name,
                query_id=tool.query_id,
                inputs=arguments,
                result_summary=f"Tool '{tool.name}' returned HTTP error {http_exc.status_code}: {http_exc.detail}",
                duration_ms=duration_ms,
                evaluated_at=now,
                outcome="error" if http_exc.status_code >= 500 else "rejected",
                warning=str(http_exc.detail),
            )
            return ToolExecutionResponse(
                tool_name=tool.name,
                status="rejected" if http_exc.status_code < 500 else "error",
                data=None,
                trace=trace,
                error_message=str(http_exc.detail),
            )
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.exception("Unexpected failure during tool execution: %s", exc)
            trace = TraceFragment(
                tool_name=tool.name,
                query_id=tool.query_id,
                inputs=arguments,
                result_summary=f"Execution error in tool '{tool.name}'.",
                duration_ms=duration_ms,
                evaluated_at=now,
                outcome="error",
                warning="Internal tool execution failure.",
            )
            return ToolExecutionResponse(
                tool_name=tool.name,
                status="error",
                data=None,
                trace=trace,
                error_message="An internal error occurred while executing the tool.",
            )
