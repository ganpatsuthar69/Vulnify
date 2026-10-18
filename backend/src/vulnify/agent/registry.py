"""Authoritative Central Tool Registry for Vulnify Agent Tools (US-601).

Responsibilities:
1. Single source of truth for tool definitions, schemas, handlers, and security classifications.
2. Enforce unique tool registration; reject duplicate names, invalid schemas, or missing handlers.
3. Expose dynamic tool metadata for FastMCP server and FastAPI endpoints without manual duplication.
"""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
import inspect
import logging
from typing import Any
from pydantic import BaseModel

from vulnify.agent.schemas import ToolClassification, ToolListResponse, ToolMetadata

logger = logging.getLogger("vulnify")


class ToolRegistrationError(Exception):
    """Raised when a tool registration fails validation or duplicates an existing tool."""


@dataclass(frozen=True)
class ToolDefinition:
    """Immutable specification for a registered agent tool."""

    name: str
    description: str
    classification: ToolClassification
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    handler: Callable[..., Coroutine[Any, Any, Any]]
    query_id: str | None = None
    requires_approval: bool = False

    def get_metadata(self) -> ToolMetadata:
        """Derive safe JSON Schema metadata for discovery."""
        schema = self.input_model.model_json_schema()
        # Clean $defs or title if needed
        return ToolMetadata(
            name=self.name,
            description=self.description,
            classification=self.classification,
            query_id=self.query_id,
            requires_approval=self.requires_approval,
            input_schema=schema,
        )


class ToolRegistry:
    """Authoritative registry storing registered tool specifications."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        """Register a new tool. Rejects duplicates, missing handlers, or invalid models."""
        if not tool.name or not tool.name.strip():
            raise ToolRegistrationError("Tool name cannot be empty.")

        name = tool.name.strip()
        if name in self._tools:
            raise ToolRegistrationError(
                f"Duplicate tool registration: Tool '{name}' is already registered."
            )

        if not callable(tool.handler):
            raise ToolRegistrationError(
                f"Invalid tool '{name}': handler must be a callable async coroutine."
            )

        if not inspect.iscoroutinefunction(tool.handler):
            raise ToolRegistrationError(
                f"Invalid tool '{name}': handler must be an asynchronous coroutine function."
            )

        if not issubclass(tool.input_model, BaseModel):
            raise ToolRegistrationError(
                f"Invalid tool '{name}': input_model must subclass Pydantic BaseModel."
            )

        if not issubclass(tool.output_model, BaseModel):
            raise ToolRegistrationError(
                f"Invalid tool '{name}': output_model must subclass Pydantic BaseModel."
            )

        if tool.classification not in ("read_only", "write_gated"):
            raise ToolRegistrationError(
                f"Invalid tool '{name}': classification must be 'read_only' or 'write_gated'."
            )

        self._tools[name] = tool
        logger.debug(
            "Registered agent tool '%s' (classification=%s, query_id=%s)",
            name,
            tool.classification,
            tool.query_id,
        )

    def get(self, name: str) -> ToolDefinition | None:
        """Lookup a registered tool by its unique name."""
        return self._tools.get(name.strip())

    def list_tools(self) -> list[ToolDefinition]:
        """Return list of all registered tool definitions in deterministic registration order."""
        return list(self._tools.values())

    def get_metadata(self) -> ToolListResponse:
        """Return discovery metadata for all registered tools."""
        metadata_list = [tool.get_metadata() for tool in self._tools.values()]
        return ToolListResponse(tools=metadata_list, total=len(metadata_list))

    def clear(self) -> None:
        """Clear the registry (used for test isolation)."""
        self._tools.clear()


# Global module singleton registry
_global_registry = ToolRegistry()
_initialized = False


def get_tool_registry() -> ToolRegistry:
    """Return the global tool registry, initializing standard tools if not already loaded."""
    global _initialized
    if not _initialized:
        _register_builtin_tools(_global_registry)
        _initialized = True
    return _global_registry


def _register_builtin_tools(registry: ToolRegistry) -> None:
    """Register the canonical initial investigation toolset for Vulnify (US-601)."""
    from vulnify.agent.tools.list_findings import list_findings_tool
    from vulnify.agent.tools.get_finding_details import get_finding_details_tool
    from vulnify.agent.tools.get_dependency_paths import get_dependency_paths_tool
    from vulnify.agent.tools.explain_finding import explain_finding_tool
    from vulnify.agent.tools.rank_findings import rank_findings_tool
    from vulnify.agent.tools.record_decision import record_decision_tool
    from vulnify.agent.tools.open_fix_issue import open_fix_issue_tool

    registry.register(list_findings_tool)
    registry.register(get_finding_details_tool)
    registry.register(get_dependency_paths_tool)
    registry.register(explain_finding_tool)
    registry.register(rank_findings_tool)
    registry.register(record_decision_tool)
    registry.register(open_fix_issue_tool)
