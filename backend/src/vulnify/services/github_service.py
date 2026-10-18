"""GitHub Remediation Issue Integration Service (US-503 / US-504).

Responsibilities:
1. Generate structured preview with cryptographic plan-hash binding (US-503).
2. Human review & CSRF approval verification bound to plan hash (US-504 AC-1).
3. Securely create real GitHub issues via GitHub REST API without leaking credentials (US-504 AC-2).
4. Idempotent duplicate prevention: re-submitting the same plan hash returns the existing issue (US-504 AC-3).
5. Concurrency protection: concurrent requests for the same plan cannot duplicate issues.
6. Safe reconciliation of uncertain outcomes and network timeouts (US-504 AC-4).
7. Comprehensive audit logging of all creation attempts, outcomes, and failure categories (US-504 AC-5).
8. Strict honesty and Markdown safety: advisory text is quoted/sanitized, never rendered as raw HTML.
"""

import asyncio
from datetime import datetime, timezone
import hashlib
import logging
import re
from typing import Any
import httpx
from fastapi import Depends, HTTPException, status

from vulnify.agent.trust_boundary import (
    quote_untrusted_markdown,
    sanitize_untrusted_text,
    verify_issue_body_structure,
)
from vulnify.config import Settings, get_settings
from vulnify.graph.vulnerability_repository import (
    IVulnerabilityRepository,
    get_vulnerability_repository,
)
from vulnify.logging import get_request_id
from vulnify.schemas import (
    GitHubIntegrationStatusResponse,
    GitHubIssueCreateRequest,
    GitHubIssueListResponse,
    GitHubIssuePreviewRequest,
    GitHubIssuePreviewResponse,
    GitHubIssueRecordResponse,
    UserResponse,
)

logger = logging.getLogger("vulnify")

# Regex to validate owner/repo format
REPO_FORMAT_REGEX = re.compile(r"^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+$")

# In-memory storage for deduplication, uncertain attempt tracking, and audit trail
_created_issues_by_hash: dict[str, GitHubIssueRecordResponse] = {}
_created_issues_by_project: dict[str, list[GitHubIssueRecordResponse]] = {}
_attempt_state_by_hash: dict[str, dict[str, Any]] = {}
_audit_trail: list[dict[str, Any]] = []

# Concurrency locks
_creation_locks: dict[str, asyncio.Lock] = {}
_global_lock = asyncio.Lock()


def reset_github_state() -> None:
    """Clear in-memory caches, attempts, and audit trail (used for test isolation)."""
    _created_issues_by_hash.clear()
    _created_issues_by_project.clear()
    _attempt_state_by_hash.clear()
    _audit_trail.clear()
    _creation_locks.clear()


def compute_plan_hash(
    project_id: str,
    finding_id: str,
    target_repo: str,
    title: str,
    body: str,
) -> str:
    """Compute a deterministic cryptographic SHA-256 plan hash binding the preview content."""
    raw = f"{project_id.strip()}:{finding_id.strip()}:{target_repo.strip()}:{title.strip()}:{body.strip()}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"plan_sha256_{digest[:16]}"


def sanitize_markdown_text(text: str | None) -> str:
    """Sanitize untrusted text to prevent raw HTML rendering or injection."""
    if not text:
        return ""
    clean = text.replace("<", "&lt;").replace(">", "&gt;")
    return clean.strip()


class GitHubService:
    """Service handling GitHub integration status, issue preview generation, and issue creation."""

    def __init__(
        self,
        settings: Settings | None = None,
        repo: IVulnerabilityRepository | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.repo = repo or get_vulnerability_repository()
        self.http_client = http_client

    def is_configured(self) -> bool:
        """Check whether GitHub integration credentials are configured."""
        token = self.settings.GITHUB_TOKEN
        return bool(token and token.strip())

    def get_default_target_repo(self) -> str:
        """Get default target repository in owner/repo format."""
        owner = (self.settings.GITHUB_DEFAULT_OWNER or "vulnify").strip()
        repo_name = (self.settings.GITHUB_DEFAULT_REPO or "demo-workspace").strip()
        return f"{owner}/{repo_name}"

    def get_status(self) -> GitHubIntegrationStatusResponse:
        """Retrieve GitHub integration configuration status without leaking credentials."""
        target_repo = self.get_default_target_repo()
        return GitHubIntegrationStatusResponse(
            configured=self.is_configured(),
            default_owner=self.settings.GITHUB_DEFAULT_OWNER,
            default_repo=self.settings.GITHUB_DEFAULT_REPO,
            target_repo=target_repo,
            api_base_url=self.settings.GITHUB_API_BASE_URL,
        )

    def validate_target_repo(self, target_repo: str) -> tuple[str, str]:
        """Validate target repository string format (owner/repo)."""
        clean_repo = target_repo.strip()
        if not REPO_FORMAT_REGEX.match(clean_repo):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid target repository format '{target_repo}'. Must be 'owner/repository'.",
            )
        parts = clean_repo.split("/")
        return parts[0], parts[1]

    def record_audit_event(
        self,
        actor: str,
        action: str,
        project_id: str,
        finding_id: str,
        plan_hash: str,
        target_repo: str,
        result: str,
        request_id: str | None = None,
        failure_category: str | None = None,
        issue_number: int | None = None,
        issue_url: str | None = None,
    ) -> dict[str, Any]:
        """Record structured audit entry without leaking credentials or raw sensitive headers."""
        now = int(datetime.now(timezone.utc).timestamp())
        event = {
            "timestamp": now,
            "actor": actor,
            "action": action,
            "project_id": project_id,
            "finding_id": finding_id,
            "plan_hash": plan_hash,
            "target_repo": target_repo,
            "result": result,
            "failure_category": failure_category,
            "request_id": request_id,
            "issue_number": issue_number,
            "issue_url": issue_url,
        }
        _audit_trail.insert(0, event)

        log_level = logging.INFO if result in ("success", "existing_issue_returned") else logging.WARNING
        logger.log(
            log_level,
            f"Audit: {action} outcome={result} repo={target_repo} actor={actor}",
            extra=event,
        )
        return event

    def get_audit_trail(self, project_id: str | None = None) -> list[dict[str, Any]]:
        """Retrieve recorded audit trail events, optionally filtered by project (US-504 AC-5)."""
        if project_id:
            return [ev for ev in _audit_trail if ev.get("project_id") == project_id]
        return list(_audit_trail)

    def generate_preview(
        self,
        project_id: str,
        finding_id: str,
        request: GitHubIssuePreviewRequest,
    ) -> GitHubIssuePreviewResponse:
        """Generate structured issue preview with deterministic plan hash (US-503)."""
        finding = self.repo.get_project_finding_detail(project_id, finding_id)
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding_id}' not found in project '{project_id}'.",
            )

        # Enforce that preview only targets the configured team-owned repository (US-504 AC-2)
        configured_repo = self.get_default_target_repo()
        if request.target_repo and request.target_repo.strip().lower() != configured_repo.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Previews can only target the configured team-owned repository '{configured_repo}'.",
            )
        target_repo = configured_repo

        pkg_name = sanitize_untrusted_text(str(finding.get("package_name", "unknown")))
        curr_ver = sanitize_untrusted_text(str(finding.get("package_version", "unknown")))
        ecosystem = sanitize_untrusted_text(str(finding.get("ecosystem", "npm")))
        adv_id = sanitize_untrusted_text(str(finding.get("advisory_id", finding_id)))
        severity = sanitize_untrusted_text(str(finding.get("severity", "UNKNOWN")))
        source_url = finding.get("source_url") or f"https://osv.dev/vulnerability/{adv_id}"
        service_name = sanitize_untrusted_text(str(finding.get("service_name") or "Main Service"))
        path_depth = finding.get("path_depth")

        # Determine target remediation version
        target_version = request.target_version or finding.get("fixed_version")
        advisory_fixed = finding.get("advisory_fixed_versions") or []
        if not target_version and advisory_fixed:
            target_version = advisory_fixed[0]
        if target_version:
            target_version = sanitize_untrusted_text(str(target_version))

        # Issue title (US-503: default pattern uses real package name)
        if request.title_override and request.title_override.strip():
            title = sanitize_untrusted_text(request.title_override.strip())
        else:
            title = f"[Vulnify] Review vulnerability in {pkg_name} ({adv_id})"

        # Build structured markdown body
        depth_desc = (
            f"Direct dependency (depth: 1 hop)"
            if path_depth == 1
            else f"Transitive dependency (depth: {path_depth} hops)"
            if path_depth
            else "Path unavailable in baseline graph"
        )

        remediation_lines = []
        if target_version:
            remediation_lines.append(f"- **Proposed Upgrade Target:** Upgrade `{pkg_name}` from `{curr_ver}` to `{target_version}`.")
            if advisory_fixed:
                remediation_lines.append(f"- **Verified Upstream Fixes:** {', '.join(f'`{v}`' for v in advisory_fixed)}")
        else:
            remediation_lines.append(f"- **Remediation Status:** No fixed version published in upstream advisory {adv_id}.")
            remediation_lines.append("- **Defensive Guidance:** Consider alternative packages, API firewalling, or isolation.")

        operator_section = ""
        if request.operator_notes and request.operator_notes.strip():
            safe_notes = sanitize_markdown_text(request.operator_notes)
            operator_section = f"\n### Operator Context & Notes\n{safe_notes}\n"

        # US-604: Include upstream advisory summary safely quoted as untrusted data
        advisory_section = ""
        adv_summary = finding.get("advisory_summary")
        adv_details = finding.get("advisory_details")
        combined_adv = []
        if adv_summary and str(adv_summary).strip():
            combined_adv.append(str(adv_summary).strip())
        if adv_details and str(adv_details).strip() and str(adv_details).strip() != str(adv_summary).strip():
            combined_adv.append(str(adv_details).strip())
        adv_text = "\n\n".join(combined_adv)
        if adv_text:
            quoted_adv = quote_untrusted_markdown(adv_text, label="Upstream Advisory Summary")
            advisory_section = f"\n### Upstream Advisory Summary (Untrusted Data)\n{quoted_adv}\n"

        body = f"""## Vulnerability Remediation Request

### Target Package & Advisory
- **Package:** `{pkg_name}`
- **Installed Version:** `{curr_ver}`
- **Ecosystem:** `{ecosystem}`
- **Advisory Reference:** [{adv_id}]({source_url})
- **Severity Rating:** **{severity}**
{advisory_section}
### Graph Evidence & Architecture Exposure
- **Affected Service Component:** `{service_name}`
- **Dependency Depth:** {depth_desc}
- **Exposure Traversal:** Verified via FalkorDB project dependency graph
> **Note:** Architectural exposure indicates structural reachability through the dependency tree; it does not constitute proof of active runtime exploitability.

### Remediation Recommendation
{chr(10).join(remediation_lines)}

### Verification Boundaries & Limitations
- **Fix Evidence:** Evaluated strictly against advisory fixed version declarations.
- **Safety Disclaimer:** Absence of detected conflicts does not guarantee runtime compatibility or application safety. Vulnify never claims an upgrade is safe to ship without project-level integration and regression testing.
{operator_section}
---
*Filed via Vulnify Graph-Powered Remediation Protocol (US-503 / US-504).*"""

        plan_hash = compute_plan_hash(project_id, finding_id, target_repo, title, body)
        configured = self.is_configured()
        warning = None if configured else "GitHub integration is not configured. Server GITHUB_TOKEN is missing or empty. Live issue creation requires server credentials."

        return GitHubIssuePreviewResponse(
            project_id=project_id,
            finding_id=finding_id,
            package_name=pkg_name,
            current_version=curr_ver,
            target_version=target_version,
            advisory_id=adv_id,
            severity=severity,
            title=title,
            body=body,
            target_repo=target_repo,
            plan_hash=plan_hash,
            can_submit=configured,
            configuration_warning=warning,
        )

    async def _reconcile_uncertain_issue(
        self,
        owner: str,
        repo_name: str,
        expected_title: str,
        expected_adv_id: str,
        headers: dict[str, str],
        timeout: float,
    ) -> tuple[int, str] | None:
        """Check whether an issue was created upstream on GitHub after an uncertain timeout."""
        api_base = self.settings.GITHUB_API_BASE_URL.rstrip("/")
        list_endpoint = f"{api_base}/repos/{owner}/{repo_name}/issues"
        params = {"state": "all", "per_page": "20", "sort": "created", "direction": "desc"}
        try:
            if self.http_client:
                res = await self.http_client.get(list_endpoint, headers=headers, params=params)
            else:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    res = await client.get(list_endpoint, headers=headers, params=params)
            if res.status_code == 200:
                for item in res.json():
                    if item.get("title") == expected_title or expected_adv_id in (item.get("body") or ""):
                        return int(item["number"]), str(item["html_url"])
        except Exception as exc:
            logger.warning("Failed to reconcile uncertain issue on GitHub: %s", exc)
        return None

    async def create_issue(
        self,
        project_id: str,
        finding_id: str,
        request: GitHubIssueCreateRequest,
        current_user: UserResponse,
    ) -> GitHubIssueRecordResponse:
        """Approve and create a real GitHub issue with plan hash verification, duplicate prevention, and concurrency safety (US-504)."""
        now = int(datetime.now(timezone.utc).timestamp())
        req_id = get_request_id()

        # 1. Human Approval Gate verification (US-504 AC-1)
        if not request.confirmed:
            self.record_audit_event(
                actor=current_user.email,
                action="create_github_issue",
                project_id=project_id,
                finding_id=finding_id,
                plan_hash=request.plan_hash,
                target_repo=request.target_repo,
                result="rejected",
                failure_category="missing_human_approval",
                request_id=req_id,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Issue creation requires explicit human approval ('confirmed': true).",
            )

        # 2. Target repository validation (Must match configured team-owned repository - US-504 AC-2)
        owner, repo_name = self.validate_target_repo(request.target_repo)
        target_repo = f"{owner}/{repo_name}"
        configured_repo = self.get_default_target_repo()
        if target_repo.lower() != configured_repo.lower():
            self.record_audit_event(
                actor=current_user.email,
                action="create_github_issue",
                project_id=project_id,
                finding_id=finding_id,
                plan_hash=request.plan_hash,
                target_repo=request.target_repo,
                result="rejected",
                failure_category="unauthorized_destination_repo",
                request_id=req_id,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Issues can only be created in the configured team-owned repository '{configured_repo}'. Arbitrary destination '{request.target_repo}' is rejected.",
            )

        # 3. Finding existence and scoping verification
        finding = self.repo.get_project_finding_detail(project_id, finding_id)
        if not finding:
            self.record_audit_event(
                actor=current_user.email,
                action="create_github_issue",
                project_id=project_id,
                finding_id=finding_id,
                plan_hash=request.plan_hash,
                target_repo=target_repo,
                result="rejected",
                failure_category="finding_not_found",
                request_id=req_id,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding_id}' not found in project '{project_id}'.",
            )

        # 4. Plan Hash Integrity Verification (US-503 / US-504)
        expected_plan_hash = compute_plan_hash(
            project_id=project_id,
            finding_id=finding_id,
            target_repo=target_repo,
            title=request.title,
            body=request.body,
        )

        if request.plan_hash != expected_plan_hash:
            self.record_audit_event(
                actor=current_user.email,
                action="create_github_issue",
                project_id=project_id,
                finding_id=finding_id,
                plan_hash=request.plan_hash,
                target_repo=target_repo,
                result="rejected",
                failure_category="plan_hash_mismatch",
                request_id=req_id,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Plan hash mismatch: the issue content or repository was modified after preview. Please re-preview the plan to review and approve changes.",
            )

        # 4b. Structural Integrity Verification (US-604)
        if not verify_issue_body_structure(request.body):
            self.record_audit_event(
                actor=current_user.email,
                action="create_github_issue",
                project_id=project_id,
                finding_id=finding_id,
                plan_hash=request.plan_hash,
                target_repo=target_repo,
                result="rejected",
                failure_category="corrupted_issue_body_structure",
                request_id=req_id,
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Issue body rejected: missing required structural remediation sections (US-604).",
            )

        # Concurrency safety: acquire per-plan lock to eliminate race conditions
        async with _global_lock:
            if request.plan_hash not in _creation_locks:
                _creation_locks[request.plan_hash] = asyncio.Lock()
            plan_lock = _creation_locks[request.plan_hash]

        async with plan_lock:
            # 5. Idempotent Duplicate Prevention (US-504 AC-3)
            if request.plan_hash in _created_issues_by_hash:
                existing = _created_issues_by_hash[request.plan_hash]
                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="existing_issue_returned",
                    request_id=req_id,
                    issue_number=existing.issue_number,
                    issue_url=existing.issue_url,
                )
                return GitHubIssueRecordResponse(
                    id=existing.id,
                    project_id=project_id,
                    finding_id=finding_id,
                    package_name=existing.package_name,
                    target_version=existing.target_version,
                    issue_number=existing.issue_number,
                    issue_url=existing.issue_url,
                    title=existing.title,
                    target_repo=existing.target_repo,
                    state=existing.state,
                    plan_hash=existing.plan_hash,
                    created_at=existing.created_at,
                    created_by=existing.created_by,
                    is_duplicate=True,
                    message=f"An issue for this exact remediation plan was already created (Issue #{existing.issue_number}). Duplicate creation prevented.",
                )

            # 6. Check GitHub Credentials
            token = self.settings.GITHUB_TOKEN
            if not token or not token.strip():
                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="failed",
                    failure_category="missing_configuration",
                    request_id=req_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="GitHub integration is not configured. Server GITHUB_TOKEN environment variable is missing.",
                )

            api_base = self.settings.GITHUB_API_BASE_URL.rstrip("/")
            issue_endpoint = f"{api_base}/repos/{owner}/{repo_name}/issues"
            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token.strip()}",
                "X-GitHub-Api-Version": self.settings.GITHUB_API_VERSION,
                "User-Agent": "Vulnify-Security-Agent",
            }
            timeout = float(self.settings.GITHUB_API_TIMEOUT_SECONDS)

            # 6b. Reconcile potential uncertain timeout from previous attempt (US-504 Section 4.6)
            prev_attempt = _attempt_state_by_hash.get(request.plan_hash)
            if prev_attempt and prev_attempt.get("status") == "timeout_uncertain":
                reconciled = await self._reconcile_uncertain_issue(
                    owner=owner,
                    repo_name=repo_name,
                    expected_title=request.title.strip(),
                    expected_adv_id=finding.get("advisory_id", finding_id),
                    headers=headers,
                    timeout=timeout,
                )
                if reconciled:
                    rec_number, rec_url = reconciled
                    rec_record = GitHubIssueRecordResponse(
                        id=f"issue-{hashlib.sha256(f'{project_id}:{target_repo}:{rec_number}'.encode('utf-8')).hexdigest()[:16]}",
                        project_id=project_id,
                        finding_id=finding_id,
                        package_name=finding.get("package_name", "unknown"),
                        target_version=request.target_version,
                        issue_number=rec_number,
                        issue_url=rec_url,
                        title=request.title,
                        target_repo=target_repo,
                        state="open",
                        plan_hash=request.plan_hash,
                        created_at=now,
                        created_by=current_user.email,
                        is_duplicate=True,
                        message=f"Reconciled existing issue #{rec_number} on GitHub following previous timeout. Duplicate creation prevented.",
                    )
                    _created_issues_by_hash[request.plan_hash] = rec_record
                    if project_id not in _created_issues_by_project:
                        _created_issues_by_project[project_id] = []
                    _created_issues_by_project[project_id].insert(0, rec_record)
                    self.record_audit_event(
                        actor=current_user.email,
                        action="create_github_issue",
                        project_id=project_id,
                        finding_id=finding_id,
                        plan_hash=request.plan_hash,
                        target_repo=target_repo,
                        result="existing_issue_returned",
                        request_id=req_id,
                        issue_number=rec_number,
                        issue_url=rec_url,
                    )
                    _attempt_state_by_hash[request.plan_hash]["status"] = "resolved"
                    return rec_record

            # 7. Execute write request to GitHub REST API
            payload = {
                "title": request.title.strip(),
                "body": request.body.strip(),
                "labels": ["security", "vulnify", "remediation"],
            }

            try:
                if self.http_client:
                    response = await self.http_client.post(issue_endpoint, json=payload, headers=headers)
                else:
                    async with httpx.AsyncClient(timeout=timeout) as client:
                        response = await client.post(issue_endpoint, json=payload, headers=headers)
            except httpx.TimeoutException as exc:
                _attempt_state_by_hash[request.plan_hash] = {
                    "status": "timeout_uncertain",
                    "timestamp": now,
                }
                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="failed",
                    failure_category="timeout_uncertain",
                    request_id=req_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail=(
                        f"GitHub API request timed out after {timeout} seconds. The creation outcome is uncertain. "
                        "A retry will safely check whether the issue was created on GitHub before attempting another write."
                    ),
                ) from exc
            except httpx.RequestError as exc:
                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="failed",
                    failure_category="connection_failure",
                    request_id=req_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to connect to GitHub API server.",
                ) from exc

            # 8. Handle GitHub Responses
            if response.status_code == 201:
                data = response.json()
                issue_number = data.get("number")
                issue_url = data.get("html_url")
                state = data.get("state", "open")

                if not issue_number or not issue_url:
                    self.record_audit_event(
                        actor=current_user.email,
                        action="create_github_issue",
                        project_id=project_id,
                        finding_id=finding_id,
                        plan_hash=request.plan_hash,
                        target_repo=target_repo,
                        result="failed",
                        failure_category="invalid_github_response",
                        request_id=req_id,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="GitHub API returned an invalid response missing issue number or URL.",
                    )

                record_id = f"issue-{hashlib.sha256(f'{project_id}:{target_repo}:{issue_number}'.encode('utf-8')).hexdigest()[:16]}"
                record = GitHubIssueRecordResponse(
                    id=record_id,
                    project_id=project_id,
                    finding_id=finding_id,
                    package_name=finding.get("package_name", "unknown"),
                    target_version=request.target_version,
                    issue_number=issue_number,
                    issue_url=issue_url,
                    title=request.title,
                    target_repo=target_repo,
                    state=state,
                    plan_hash=request.plan_hash,
                    created_at=now,
                    created_by=current_user.email,
                    is_duplicate=False,
                    message=f"GitHub issue #{issue_number} successfully created in {target_repo}.",
                )

                _created_issues_by_hash[request.plan_hash] = record
                if project_id not in _created_issues_by_project:
                    _created_issues_by_project[project_id] = []
                _created_issues_by_project[project_id].insert(0, record)

                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="success",
                    request_id=req_id,
                    issue_number=issue_number,
                    issue_url=issue_url,
                )
                return record

            # Upstream error status mapping
            if response.status_code == 401:
                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="failed",
                    failure_category="unauthorized_github_token",
                    request_id=req_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="GitHub authentication failed. Configured GITHUB_TOKEN is invalid or expired.",
                )
            elif response.status_code == 403:
                remaining = response.headers.get("x-ratelimit-remaining")
                if remaining == "0":
                    self.record_audit_event(
                        actor=current_user.email,
                        action="create_github_issue",
                        project_id=project_id,
                        finding_id=finding_id,
                        plan_hash=request.plan_hash,
                        target_repo=target_repo,
                        result="failed",
                        failure_category="rate_limited",
                        request_id=req_id,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="GitHub API rate limit exceeded. Please retry after rate limit resets.",
                    )
                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="failed",
                    failure_category="permission_denied",
                    request_id=req_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"GitHub token lacks permission to create issues in repository '{target_repo}'. Token requires 'Issues: Read and write' permission.",
                )
            elif response.status_code == 404:
                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="failed",
                    failure_category="repository_not_found",
                    request_id=req_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"GitHub repository '{target_repo}' not found or token lacks access.",
                )
            elif response.status_code == 422:
                try:
                    err_data = response.json()
                    msg = err_data.get("message", "Validation failed")
                except Exception:
                    msg = response.text
                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="failed",
                    failure_category="rejected_payload",
                    request_id=req_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"GitHub rejected issue payload: {msg}",
                )
            else:
                self.record_audit_event(
                    actor=current_user.email,
                    action="create_github_issue",
                    project_id=project_id,
                    finding_id=finding_id,
                    plan_hash=request.plan_hash,
                    target_repo=target_repo,
                    result="failed",
                    failure_category="upstream_github_error",
                    request_id=req_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Upstream GitHub API error (status {response.status_code}).",
                )

    def list_project_issues(self, project_id: str) -> GitHubIssueListResponse:
        """Retrieve list of created remediation issues for the project (US-505)."""
        items = _created_issues_by_project.get(project_id, [])
        return GitHubIssueListResponse(items=items, total=len(items))


def get_github_service(
    settings: Settings = Depends(get_settings),
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
) -> GitHubService:
    return GitHubService(settings=settings, repo=repo)
