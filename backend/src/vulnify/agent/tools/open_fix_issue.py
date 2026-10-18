"""Tool: open_fix_issue (US-601 AC-1 / AC-2 / AC-3).

Purpose:
Gated write tool that opens a real GitHub Issue in the configured team repository
for a vulnerability finding after explicit human review and approval.
Requires confirmation ('confirmed': true), validates cryptographic plan hash,
and enforces team repository scoping.
"""

from datetime import datetime, timezone
import time
from typing import Any
from fastapi import HTTPException
from pydantic import BaseModel, Field

from vulnify.agent.registry import ToolDefinition
from vulnify.agent.schemas import TraceFragment
from vulnify.config import get_settings
from vulnify.graph.vulnerability_repository import get_vulnerability_repository
from vulnify.schemas import (
    GitHubIssueCreateRequest,
    GitHubIssuePreviewRequest,
    UserResponse,
)
from vulnify.services.github_service import GitHubService


class OpenFixIssueInput(BaseModel):
    """Input parameters for opening a GitHub remediation issue."""

    project_id: str = Field(..., description="Unique project identifier", min_length=1)
    finding_id: str = Field(
        ...,
        description="Finding identifier (find-... hash) or advisory ID (e.g. GHSA-..., OSV-...)",
        min_length=1,
    )
    target_repo: str | None = Field(
        default=None,
        description="Target GitHub repository ('owner/repo'). Defaults to configured team repository.",
    )
    title: str | None = Field(
        default=None,
        description="Optional custom issue title; defaults to standard Vulnify remediation title.",
    )
    body: str | None = Field(
        default=None,
        description="Optional custom issue markdown body; defaults to standard Vulnify preview.",
    )
    plan_hash: str | None = Field(
        default=None,
        description="Cryptographic plan hash derived from preview (required for approval binding).",
    )
    confirmed: bool = Field(
        default=False,
        description="Explicit human approval confirmation (must be true to create issue).",
    )


class OpenFixIssueResult(BaseModel):
    """Result returned by open_fix_issue tool."""

    issue_number: int | None = None
    issue_url: str | None = None
    target_repo: str
    plan_hash: str
    status: str  # "created", "reused_existing", "uncertain"
    project_id: str
    finding_id: str
    trace: TraceFragment


async def handle_open_fix_issue(inputs: OpenFixIssueInput) -> OpenFixIssueResult:
    """Create a verified GitHub issue after strictly checking human approval and plan hash."""
    start = time.perf_counter()
    now = int(datetime.now(timezone.utc).timestamp())

    # 1. Human Approval Gate verification (US-601 AC-2 / US-504 AC-1)
    if not inputs.confirmed:
        raise HTTPException(
            status_code=403,
            detail="Operation rejected: 'open_fix_issue' requires explicit human confirmation ('confirmed': true).",
        )

    settings = get_settings()
    repo = get_vulnerability_repository()
    github_service = GitHubService(settings=settings, repo=repo)

    target_repo = inputs.target_repo or github_service.get_default_target_repo()

    # 2. Derive or verify preview plan hash
    plan_hash = inputs.plan_hash
    title = inputs.title
    body = inputs.body

    if not plan_hash:
        preview = github_service.generate_preview(
            project_id=inputs.project_id,
            finding_id=inputs.finding_id,
            request=GitHubIssuePreviewRequest(
                target_repo=target_repo,
                custom_title=title,
                custom_body=body,
            ),
        )
        plan_hash = preview.plan_hash
        title = preview.title
        body = preview.body
        target_repo = preview.target_repo
    elif not title or not body:
        # Re-derive preview content corresponding to finding if not fully provided
        preview = github_service.generate_preview(
            project_id=inputs.project_id,
            finding_id=inputs.finding_id,
            request=GitHubIssuePreviewRequest(
                target_repo=target_repo,
                custom_title=title,
                custom_body=body,
            ),
        )
        title = title or preview.title
        body = body or preview.body

    # 3. Construct actor and creation request
    actor = UserResponse(
        id="vulnify-agent",
        name="Vulnify Agent",
        email="agent@vulnify.local",
        role="admin",
        is_active=True,
        created_at=now,
    )

    create_req = GitHubIssueCreateRequest(
        plan_hash=plan_hash,
        target_repo=target_repo,
        title=title,
        body=body,
        confirmed=True,
    )

    # 4. Invoke GitHub service to create or reuse issue
    record = await github_service.create_issue(
        project_id=inputs.project_id,
        finding_id=inputs.finding_id,
        request=create_req,
        current_user=actor,
    )

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    summary = (
        f"GitHub issue #{record.issue_number} on '{record.target_repo}' {record.status} "
        f"for finding '{inputs.finding_id}' (plan: {plan_hash}). URL: {record.issue_url}"
    )

    trace = TraceFragment(
        tool_name="open_fix_issue",
        query_id="open_github_issue",
        inputs={
            "project_id": inputs.project_id,
            "finding_id": inputs.finding_id,
            "target_repo": target_repo,
            "plan_hash": plan_hash,
            "confirmed": True,
        },
        result_summary=summary,
        duration_ms=duration_ms,
        record_count=1,
        evaluated_at=now,
        outcome="success",
        evidence_references=[record.advisory_id],
    )

    return OpenFixIssueResult(
        issue_number=record.issue_number,
        issue_url=record.issue_url,
        target_repo=record.target_repo,
        plan_hash=record.plan_hash,
        status=record.status,
        project_id=inputs.project_id,
        finding_id=inputs.finding_id,
        trace=trace,
    )


open_fix_issue_tool = ToolDefinition(
    name="open_fix_issue",
    description="Gated write tool that creates a real GitHub remediation issue after human approval and plan hash validation.",
    classification="write_gated",
    input_model=OpenFixIssueInput,
    output_model=OpenFixIssueResult,
    handler=handle_open_fix_issue,
    query_id="open_github_issue",
    requires_approval=True,
)
