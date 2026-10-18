"""Unit tests for Authoritative Tool Registry (US-601 AC-1)."""

import pytest
from pydantic import BaseModel, Field

from vulnify.agent.registry import (
    ToolDefinition,
    ToolRegistrationError,
    ToolRegistry,
    get_tool_registry,
)
from vulnify.agent.schemas import TraceFragment


class DummyInput(BaseModel):
    name: str = Field(..., min_length=1)
    limit: int = Field(default=10, ge=1)


class DummyOutput(BaseModel):
    greeting: str
    trace: TraceFragment


async def dummy_handler(inputs: DummyInput) -> DummyOutput:
    trace = TraceFragment(
        tool_name="dummy_tool",
        result_summary="Success",
        duration_ms=1.0,
        evaluated_at=1000,
        outcome="success",
    )
    return DummyOutput(greeting=f"Hello, {inputs.name}!", trace=trace)


def test_registry_valid_registration() -> None:
    registry = ToolRegistry()
    tool = ToolDefinition(
        name="test_tool",
        description="A test tool",
        classification="read_only",
        input_model=DummyInput,
        output_model=DummyOutput,
        handler=dummy_handler,
        query_id="dummy_query",
    )

    registry.register(tool)
    assert registry.get("test_tool") is tool
    assert len(registry.list_tools()) == 1


def test_registry_rejects_duplicate_registration() -> None:
    registry = ToolRegistry()
    tool = ToolDefinition(
        name="test_tool",
        description="A test tool",
        classification="read_only",
        input_model=DummyInput,
        output_model=DummyOutput,
        handler=dummy_handler,
    )
    registry.register(tool)

    with pytest.raises(ToolRegistrationError, match="already registered"):
        registry.register(tool)


def test_registry_rejects_invalid_names() -> None:
    registry = ToolRegistry()
    with pytest.raises(ToolRegistrationError, match="name cannot be empty"):
        ToolDefinition(
            name="   ",
            description="Blank name",
            classification="read_only",
            input_model=DummyInput,
            output_model=DummyOutput,
            handler=dummy_handler,
        )
        registry.register(
            ToolDefinition(
                name=" ",
                description="desc",
                classification="read_only",
                input_model=DummyInput,
                output_model=DummyOutput,
                handler=dummy_handler,
            )
        )


def test_registry_rejects_sync_handler() -> None:
    registry = ToolRegistry()

    def sync_handler(inputs: DummyInput) -> DummyOutput:
        raise NotImplementedError

    with pytest.raises(ToolRegistrationError, match="handler must be an asynchronous coroutine"):
        registry.register(
            ToolDefinition(
                name="sync_tool",
                description="desc",
                classification="read_only",
                input_model=DummyInput,
                output_model=DummyOutput,
                handler=sync_handler,  # type: ignore[arg-type]
            )
        )


def test_registry_rejects_invalid_models() -> None:
    registry = ToolRegistry()

    class NotABaseModel:
        pass

    with pytest.raises(ToolRegistrationError, match="input_model must subclass Pydantic BaseModel"):
        registry.register(
            ToolDefinition(
                name="bad_input_tool",
                description="desc",
                classification="read_only",
                input_model=NotABaseModel,  # type: ignore[arg-type]
                output_model=DummyOutput,
                handler=dummy_handler,
            )
        )

    with pytest.raises(ToolRegistrationError, match="output_model must subclass Pydantic BaseModel"):
        registry.register(
            ToolDefinition(
                name="bad_output_tool",
                description="desc",
                classification="read_only",
                input_model=DummyInput,
                output_model=NotABaseModel,  # type: ignore[arg-type]
                handler=dummy_handler,
            )
        )


def test_global_registry_initializes_canonical_tools() -> None:
    reg = get_tool_registry()
    tools = reg.list_tools()
    assert len(tools) == 7

    names = {t.name for t in tools}
    expected = {
        "list_findings",
        "get_finding_details",
        "get_dependency_paths",
        "explain_finding",
        "rank_findings",
        "record_decision",
        "open_fix_issue",
    }
    assert names == expected

    # Verify write tools are strictly gated
    record_tool = reg.get("record_decision")
    assert record_tool is not None
    assert record_tool.classification == "write_gated"
    assert record_tool.requires_approval is True

    issue_tool = reg.get("open_fix_issue")
    assert issue_tool is not None
    assert issue_tool.classification == "write_gated"
    assert issue_tool.requires_approval is True

    # Verify read tools are read_only and un-gated
    read_tools = ["list_findings", "get_finding_details", "get_dependency_paths", "explain_finding", "rank_findings"]
    for rt_name in read_tools:
        rt = reg.get(rt_name)
        assert rt is not None
        assert rt.classification == "read_only"
        assert rt.requires_approval is False


def test_registry_derives_valid_metadata_schemas() -> None:
    reg = get_tool_registry()
    metadata_response = reg.get_metadata()
    assert metadata_response.total == 7

    meta_map = {m.name: m for m in metadata_response.tools}
    paths_tool_meta = meta_map["get_dependency_paths"]
    assert paths_tool_meta.classification == "read_only"
    assert paths_tool_meta.query_id == "get_project_finding_paths"
    assert "project_id" in paths_tool_meta.input_schema["properties"]
    assert "max_depth" in paths_tool_meta.input_schema["properties"]
