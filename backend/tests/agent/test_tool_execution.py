"""Unit tests for controlled agent tool execution and parameterized queries (US-601)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from vulnify.agent.executor import ToolExecutor
from vulnify.agent.registry import get_tool_registry
from vulnify.agent.tools.explain_finding import handle_explain_finding, ExplainFindingInput
from vulnify.agent.tools.get_dependency_paths import handle_get_dependency_paths, GetDependencyPathsInput
from vulnify.agent.tools.get_finding_details import handle_get_finding_details, GetFindingDetailsInput
from vulnify.agent.tools.list_findings import handle_list_findings, ListFindingsInput
from vulnify.agent.tools.open_fix_issue import handle_open_fix_issue, OpenFixIssueInput
from vulnify.agent.tools.rank_findings import handle_rank_findings, RankFindingsInput
from vulnify.agent.tools.record_decision import handle_record_decision, RecordDecisionInput
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository


@pytest.fixture
def test_repo() -> InMemoryVulnerabilityRepository:
    repo = InMemoryVulnerabilityRepository()
    proj_id = "test-proj"
    repo.findings_override[proj_id] = [
        {
            "id": "find-1",
            "project_id": proj_id,
            "service_id": "svc-1",
            "service_name": "api-gateway",
            "advisory_id": "GHSA-1234",
            "advisory_summary": "Sample high severity flaw",
            "severity": "HIGH",
            "priority": "High",
            "priority_reasons": ["High severity advisory with discovered reachability"],
            "scoring_version": "v1.0.0",
            "status": "open",
            "package_version_id": "pkg-lodash-4.17.20",
            "package_name": "lodash",
            "package_version": "4.17.20",
            "ecosystem": "npm",
            "matched_range": "< 4.17.21",
            "fixed_version": "4.17.21",
            "path_depth": 2,
            "path_status": "path_found",
            "aliases": ["CVE-2021-23337"],
        },
        {
            "id": "find-2",
            "project_id": proj_id,
            "service_id": "svc-2",
            "service_name": "worker-svc",
            "advisory_id": "GHSA-5678",
            "advisory_summary": "Critical RCE",
            "severity": "CRITICAL",
            "priority": "Highest",
            "priority_reasons": ["Critical severity advisory on direct dependency"],
            "scoring_version": "v1.0.0",
            "status": "open",
            "package_version_id": "pkg-axios-0.21.1",
            "package_name": "axios",
            "package_version": "0.21.1",
            "ecosystem": "npm",
            "matched_range": "< 0.21.2",
            "fixed_version": "0.21.2",
            "path_depth": 1,
            "path_status": "path_found",
            "aliases": [],
        },
    ]

    # Add mock custom paths
    repo.custom_paths[("svc-1", "pkg-lodash-4.17.20")] = [
        {
            "id": "path-1",
            "depth": 2,
            "is_direct": False,
            "nodes": [
                {"id": "svc-1", "node_type": "service", "display_name": "api-gateway"},
                {"id": "pkg-middle-1.0.0", "node_type": "package", "display_name": "middleware@1.0.0", "package_name": "middleware", "package_version": "1.0.0"},
                {"id": "pkg-lodash-4.17.20", "node_type": "package", "display_name": "lodash@4.17.20", "package_name": "lodash", "package_version": "4.17.20"},
            ],
            "edges": [
                {"id": "e1", "source_id": "svc-1", "target_id": "pkg-middle-1.0.0", "relationship_type": "DEPENDS_ON", "direct": True},
                {"id": "e2", "source_id": "pkg-middle-1.0.0", "target_id": "pkg-lodash-4.17.20", "relationship_type": "DEPENDS_ON", "direct": False},
            ],
            "summary_text": "Service: api-gateway → middleware@1.0.0 → lodash@4.17.20",
        }
    ]
    repo.custom_paths[("svc-2", "pkg-axios-0.21.1")] = []

    return repo


@pytest.mark.asyncio
async def test_tool_list_findings(test_repo: InMemoryVulnerabilityRepository) -> None:
    with patch("vulnify.agent.tools.list_findings.get_vulnerability_repository", return_value=test_repo):
        res = await handle_list_findings(ListFindingsInput(project_id="test-proj", page=1, page_size=10))
        assert res.total == 2
        assert len(res.items) == 2
        assert res.trace.outcome == "success"
        assert res.trace.query_id == "get_project_findings"
        assert res.trace.record_count == 2


@pytest.mark.asyncio
async def test_tool_get_finding_details(test_repo: InMemoryVulnerabilityRepository) -> None:
    with patch("vulnify.agent.tools.get_finding_details.get_vulnerability_repository", return_value=test_repo):
        # Found
        res_found = await handle_get_finding_details(GetFindingDetailsInput(project_id="test-proj", finding_id="find-1"))
        assert res_found.found is True
        assert res_found.finding is not None
        assert res_found.finding.package_name == "lodash"
        assert res_found.trace.outcome == "success"
        assert res_found.trace.query_id == "get_project_finding_detail"

        # Not found
        res_missing = await handle_get_finding_details(GetFindingDetailsInput(project_id="test-proj", finding_id="nonexistent"))
        assert res_missing.found is False
        assert res_missing.finding is None
        assert res_missing.trace.outcome == "empty"


@pytest.mark.asyncio
async def test_tool_get_dependency_paths(test_repo: InMemoryVulnerabilityRepository) -> None:
    with patch("vulnify.agent.tools.get_dependency_paths.get_vulnerability_repository", return_value=test_repo):
        # Path found
        res_paths = await handle_get_dependency_paths(GetDependencyPathsInput(project_id="test-proj", finding_id="find-1"))
        assert res_paths.has_path is True
        assert len(res_paths.paths) == 1
        assert res_paths.paths[0].depth == 2
        assert res_paths.paths[0].is_direct is False
        assert res_paths.trace.outcome == "success"

        # Path not found
        res_no_path = await handle_get_dependency_paths(GetDependencyPathsInput(project_id="test-proj", finding_id="find-2"))
        assert res_no_path.has_path is False
        assert res_no_path.paths == []
        assert res_no_path.trace.outcome == "no_path"
        assert "No dependency path found" in (res_no_path.no_path_message or "")
        assert "Absence of a dependency path" in (res_no_path.trace.warning or "")


@pytest.mark.asyncio
async def test_tool_explain_finding(test_repo: InMemoryVulnerabilityRepository) -> None:
    with patch("vulnify.agent.tools.explain_finding.get_vulnerability_repository", return_value=test_repo):
        res = await handle_explain_finding(ExplainFindingInput(project_id="test-proj", finding_id="find-1"))
        assert res.found is True
        assert res.explanation is not None
        assert res.explanation.exposure_type == "transitive"
        assert res.explanation.path_depth == 2
        assert "architectural exposure" in res.explanation.non_exploitability_disclaimer
        assert "not proof of runtime exploitability" in res.summary_text
        assert res.trace.outcome == "success"


@pytest.mark.asyncio
async def test_tool_rank_findings(test_repo: InMemoryVulnerabilityRepository) -> None:
    with patch("vulnify.agent.tools.rank_findings.get_vulnerability_repository", return_value=test_repo):
        res = await handle_rank_findings(RankFindingsInput(project_id="test-proj", limit=10))
        assert res.total_findings == 2
        assert res.scoring_version == "v1.0.0"
        assert res.distribution.highest == 1
        assert res.distribution.high == 1
        # Highest ranked first
        assert res.ranked_findings[0].priority == "Highest"
        assert res.ranked_findings[0].advisory_id == "GHSA-5678"
        assert res.trace.outcome == "success"


@pytest.mark.asyncio
async def test_tool_record_decision_gating(test_repo: InMemoryVulnerabilityRepository) -> None:
    executor = ToolExecutor()
    with patch("vulnify.agent.tools.record_decision.get_vulnerability_repository", return_value=test_repo):
        # 1. Unconfirmed attempt blocked by executor
        rejected_resp = await executor.execute(
            tool_name="record_decision",
            arguments={
                "project_id": "test-proj",
                "finding_id": "find-1",
                "status": "affected",
                "confirmed": False,
            },
        )
        assert rejected_resp.status == "rejected"
        assert rejected_resp.trace.outcome == "rejected"
        assert "explicit human approval is required" in (rejected_resp.error_message or "")

        # 2. Validation error: 'not_affected' requires justification >= 10 chars
        invalid_just_resp = await executor.execute(
            tool_name="record_decision",
            arguments={
                "project_id": "test-proj",
                "finding_id": "find-1",
                "status": "not_affected",
                "justification": "short",
                "confirmed": True,
            },
        )
        assert invalid_just_resp.status == "error"
        assert "justification of at least 10 characters" in (invalid_just_resp.error_message or "")

        # 3. Successful execution when confirmed and valid
        success_resp = await executor.execute(
            tool_name="record_decision",
            arguments={
                "project_id": "test-proj",
                "finding_id": "find-1",
                "status": "not_affected",
                "justification": "This service does not invoke vulnerable API routes.",
                "confirmed": True,
            },
        )
        assert success_resp.status == "success"
        assert success_resp.data.success is True
        assert success_resp.data.new_status == "not_affected"
        assert success_resp.trace.outcome == "success"


@pytest.mark.asyncio
async def test_tool_open_fix_issue_gating(test_repo: InMemoryVulnerabilityRepository) -> None:
    executor = ToolExecutor()

    # 1. Unconfirmed attempt blocked
    rejected_resp = await executor.execute(
        tool_name="open_fix_issue",
        arguments={
            "project_id": "test-proj",
            "finding_id": "find-1",
            "confirmed": False,
        },
    )
    assert rejected_resp.status == "rejected"
    assert rejected_resp.trace.outcome == "rejected"
    assert "explicit human approval is required" in (rejected_resp.error_message or "")

    # 2. Confirmed invocation delegates to GitHubService
    mock_record = MagicMock()
    mock_record.issue_number = 42
    mock_record.issue_url = "https://github.com/vulnify/demo-workspace/issues/42"
    mock_record.target_repo = "vulnify/demo-workspace"
    mock_record.plan_hash = "plan_sha256_mockhash12345"
    mock_record.status = "created"
    mock_record.advisory_id = "GHSA-1234"

    with patch("vulnify.agent.tools.open_fix_issue.GitHubService.create_issue", new_callable=AsyncMock) as mock_create, \
         patch("vulnify.agent.tools.open_fix_issue.get_vulnerability_repository", return_value=test_repo):
        mock_create.return_value = mock_record

        success_resp = await executor.execute(
            tool_name="open_fix_issue",
            arguments={
                "project_id": "test-proj",
                "finding_id": "find-1",
                "plan_hash": "plan_sha256_mockhash12345",
                "title": "Fix lodash flaw",
                "body": "Markdown body with evidence",
                "confirmed": True,
            },
        )
        assert success_resp.status == "success"
        assert success_resp.data.issue_number == 42
        assert success_resp.data.issue_url == "https://github.com/vulnify/demo-workspace/issues/42"
        assert success_resp.trace.outcome == "success"
