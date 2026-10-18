"""FastMCP Server for Vulnify Agent Tools (US-601).

Responsibilities:
1. Exposes the authoritative ToolRegistry over the Model Context Protocol (MCP).
2. Dynamically derives tool schemas, names, and descriptions from the central registry
   without duplicating tool definitions.
3. Routes all tool invocations through ToolExecutor, guaranteeing that:
   - Parameterized queries are enforced.
   - Gated write tools require explicit human confirmation.
   - Execution duration, evidence, and TraceFragments are captured.
4. Provides standard transport adapters (SSE, stdio) for integration with LLM agents.
"""

from collections.abc import Callable
import inspect
import json
import logging
from typing import Any
from mcp.server.mcpserver import MCPServer

from vulnify.agent.executor import ToolExecutor
from vulnify.agent.registry import ToolDefinition, ToolRegistry, get_tool_registry

logger = logging.getLogger("vulnify")

# FastMCP alias for semantic consistency with project specs
FastMCP = MCPServer


def _build_mcp_tool_wrapper(
    tool_def: ToolDefinition,
    executor: ToolExecutor,
) -> Callable[..., Any]:
    """Dynamically construct a typed coroutine for MCPServer tool registration.

    Inspects tool_def.input_model to build an explicit inspect.Signature so that
    MCPServer's schema generator derives the exact input parameters and types.
    """
    input_cls = tool_def.input_model

    sig_params: list[inspect.Parameter] = []
    for field_name, field_info in input_cls.model_fields.items():
        default_val = (
            inspect.Parameter.empty
            if field_info.is_required()
            else field_info.default
        )
        sig_params.append(
            inspect.Parameter(
                name=field_name,
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default_val,
                annotation=field_info.annotation,
            )
        )

    async def tool_handler(**kwargs: Any) -> dict[str, Any]:
        """Dynamically dispatched handler routing through ToolExecutor."""
        # Clean out kwargs that may be unset defaults or empty values
        response = await executor.execute(
            tool_name=tool_def.name,
            arguments=kwargs,
            actor_email="mcp-client@vulnify.local",
            is_admin=True,
        )

        resp_dict = response.model_dump()
        if response.status == "rejected":
            logger.warning(
                "MCP tool '%s' rejected: %s",
                tool_def.name,
                response.error_message,
            )
            # Return structured response indicating rejection
            return resp_dict

        if response.status == "error":
            logger.error(
                "MCP tool '%s' error: %s",
                tool_def.name,
                response.error_message,
            )
            return resp_dict

        return resp_dict

    tool_handler.__name__ = tool_def.name
    tool_handler.__doc__ = tool_def.description
    tool_handler.__signature__ = inspect.Signature(sig_params)  # type: ignore[attr-defined]

    return tool_handler


def create_mcp_server(
    registry: ToolRegistry | None = None,
    executor: ToolExecutor | None = None,
    server_name: str = "vulnify-mcp",
) -> MCPServer:
    """Create and configure an MCPServer exposing all registered agent tools."""
    target_registry = registry or get_tool_registry()
    target_executor = executor or ToolExecutor(registry=target_registry)

    server = MCPServer(server_name)

    registered_tools = target_registry.list_tools()
    for tool_def in registered_tools:
        wrapper = _build_mcp_tool_wrapper(tool_def, target_executor)
        server.add_tool(
            fn=wrapper,
            name=tool_def.name,
            description=tool_def.description,
        )
        logger.debug(
            "Registered MCP tool '%s' (classification=%s, query_id=%s)",
            tool_def.name,
            tool_def.classification,
            tool_def.query_id,
        )

    return server


_global_mcp_server: MCPServer | None = None


def get_mcp_server() -> MCPServer:
    """Retrieve or lazily initialize the application MCP server."""
    global _global_mcp_server
    if _global_mcp_server is None:
        _global_mcp_server = create_mcp_server()
    return _global_mcp_server
