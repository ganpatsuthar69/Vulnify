"""Unit tests for FastMCP server integration and tool invocation (US-601 AC-2)."""

import pytest
from unittest.mock import patch

from vulnify.agent.mcp_server import create_mcp_server
from vulnify.agent.registry import get_tool_registry
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository


@pytest.fixture
def mcp_test_repo() -> InMemoryVulnerabilityRepository:
    repo = InMemoryVulnerabilityRepository()
    repo.findings_override["proj-mcp"] = [
        {
            "id": "find-mcp-1",
            "project_id": "proj-mcp",
            "service_id": "svc-mcp",
            "service_name": "web-api",
            "advisory_id": "GHSA-9999",
            "advisory_summary": "Sample advisory",
            "severity": "MEDIUM",
            "priority": "Medium",
            "priority_reasons": ["Discovered reachability"],
            "scoring_version": "v1.0.0",
            "status": "open",
            "package_version_id": "pkg-semver-7.3.5",
            "package_name": "semver",
            "package_version": "7.3.5",
            "ecosystem": "npm",
            "matched_range": "< 7.5.2",
            "fixed_version": "7.5.2",
            "path_depth": 1,
            "path_status": "path_found",
            "aliases": [],
        }
    ]
    return repo


@pytest.mark.asyncio
async def test_mcp_server_lists_all_tools() -> None:
    server = create_mcp_server()
    tools = await server.list_tools()

    tool_names = {t.name for t in tools}
    assert len(tool_names) == 7
    expected = {
        "list_findings",
        "get_finding_details",
        "get_dependency_paths",
        "explain_finding",
        "rank_findings",
        "record_decision",
        "open_fix_issue",
    }
    assert tool_names == expected

    # Verify input_schema presence
    for t in tools:
        assert t.input_schema is not None
        assert "properties" in t.input_schema


@pytest.mark.asyncio
async def test_mcp_server_call_read_only_tool(mcp_test_repo: InMemoryVulnerabilityRepository) -> None:
    server = create_mcp_server()
    with patch("vulnify.agent.tools.list_findings.get_vulnerability_repository", return_value=mcp_test_repo):
        result = await server.call_tool("list_findings", {"project_id": "proj-mcp", "page": 1, "page_size": 10})
        assert result is not None
        assert result.content is not None
        assert len(result.content) > 0

        text = result.content[0].text
        assert "find-mcp-1" in text
        assert "GHSA-9999" in text
        assert "get_project_findings" in text


@pytest.mark.asyncio
async def test_mcp_server_gated_write_tool_rejection(mcp_test_repo: InMemoryVulnerabilityRepository) -> None:
    server = create_mcp_server()
    with patch("vulnify.agent.tools.record_decision.get_vulnerability_repository", return_value=mcp_test_repo):
        # Attempt execution with confirmed=False
        result = await server.call_tool(
            "record_decision",
            {
                "project_id": "proj-mcp",
                "finding_id": "find-mcp-1",
                "status": "affected",
                "confirmed": False,
            },
        )
        assert result is not None
        text = result.content[0].text
        assert "rejected" in text
        assert "explicit human approval is required" in text


@pytest.mark.asyncio
async def test_mcp_server_gated_write_tool_success_when_confirmed(mcp_test_repo: InMemoryVulnerabilityRepository) -> None:
    server = create_mcp_server()
    with patch("vulnify.agent.tools.record_decision.get_vulnerability_repository", return_value=mcp_test_repo):
        result = await server.call_tool(
            "record_decision",
            {
                "project_id": "proj-mcp",
                "finding_id": "find-mcp-1",
                "status": "not_affected",
                "justification": "Verified internal network route does not invoke this library.",
                "confirmed": True,
            },
        )
        assert result is not None
        text = result.content[0].text
        assert "success" in text
        assert "not_affected" in text
