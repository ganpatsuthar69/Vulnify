"""Agent Orchestrator and Streaming Run Manager for Vulnify (US-602).

Responsibilities:
1. Manages agent run lifecycle: accepted -> running -> completed | cancelled | timeout | step_limit_reached | failed.
2. Enforces step limits (AGENT_STEP_LIMIT) and wall-clock timeouts (AGENT_RUN_TIMEOUT_SECONDS).
3. Provides run-scoped cancellation via asyncio.Event, preventing cancellation of other users' runs.
4. Executes registered US-601 tools dynamically through ToolExecutor, never writing raw Cypher or shell commands.
5. Emits typed Server-Sent Events (SSE) incrementally (tool_started, tool_completed, answer_delta, etc.).
6. Generates answers strictly grounded in graph tool outputs, citing real finding IDs and dependency paths.
"""

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import re
import time
from typing import Any
import uuid

from vulnify.agent.executor import ToolExecutor
from vulnify.agent.registry import ToolRegistry, get_tool_registry
from vulnify.agent.schemas import (
    AgentRunCancelResponse,
    AgentRunState,
    AgentRunStatusResponse,
    AgentStreamEvent,
    ToolExecutionResponse,
)
from vulnify.config import Settings, get_settings
from vulnify.graph.agent_run_repository import (
    AgentRunRecord,
    AgentToolCallRecord,
    IAgentRunRepository,
    get_agent_run_repository,
    sanitize_tool_inputs,
)
from vulnify.graph.project_repository import IProjectRepository, get_project_repository

logger = logging.getLogger("vulnify")


@dataclass
class RunContext:
    """Isolated execution context for an active agent run."""

    run_id: str
    project_id: str
    user_id: str
    user_email: str
    status: AgentRunState
    prompt: str = ""
    step_count: int = 0
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    created_at: int = field(default_factory=lambda: int(datetime.now(timezone.utc).timestamp()))
    completed_at: int | None = None
    final_answer: str | None = None
    error_message: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    findings_referenced: set[str] = field(default_factory=set)
    paths_referenced: list[str] = field(default_factory=list)


class AgentOrchestrator:
    """Orchestrates step budgets, timeouts, tool dispatches, durable persistence, and SSE streaming."""

    def __init__(
        self,
        settings: Settings | None = None,
        registry: ToolRegistry | None = None,
        project_repo: IProjectRepository | None = None,
        agent_run_repo: IAgentRunRepository | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.registry = registry or get_tool_registry()
        self.project_repo = project_repo or get_project_repository()
        self.agent_run_repo = agent_run_repo or get_agent_run_repository()
        self.executor = ToolExecutor(registry=self.registry)
        self._active_runs: dict[str, RunContext] = {}
        self._lock = asyncio.Lock()

    def _persist_run(self, run: RunContext) -> None:
        """Durable persistence hook for AgentRun state changes."""
        try:
            rec = AgentRunRecord(
                id=run.run_id,
                project_id=run.project_id,
                user_id=run.user_id,
                user_email=run.user_email,
                prompt=run.prompt,
                status=run.status,
                started_at=run.created_at,
                completed_at=run.completed_at,
                final_answer=run.final_answer,
                error_message=run.error_message,
                step_count=run.step_count,
                findings_referenced=sorted(list(run.findings_referenced)),
                paths_referenced=run.paths_referenced,
                tool_call_count=len(run.tool_calls),
            )
            self.agent_run_repo.upsert_run(rec)
        except Exception as exc:
            logger.warning("Failed to persist AgentRun '%s': %s", run.run_id, exc)

    def _persist_tool_call(self, tool_call: AgentToolCallRecord) -> None:
        """Durable persistence hook for individual AgentToolCall executions."""
        try:
            self.agent_run_repo.upsert_tool_call(tool_call)
        except Exception as exc:
            logger.warning("Failed to persist AgentToolCall '%s': %s", tool_call.id, exc)

    def get_run(self, run_id: str) -> RunContext | None:
        """Lookup active or recent run context, falling back to durable store."""
        if run_id in self._active_runs:
            return self._active_runs[run_id]

        # Check repository if available
        if hasattr(self.agent_run_repo, "_runs"):
            r = getattr(self.agent_run_repo, "_runs", {}).get(run_id)
            if r:
                return RunContext(
                    run_id=r.id,
                    project_id=r.project_id,
                    user_id=r.user_id,
                    user_email=r.user_email,
                    status=r.status,
                    prompt=r.prompt,
                    step_count=r.step_count,
                    created_at=r.started_at,
                    completed_at=r.completed_at,
                    final_answer=r.final_answer,
                    error_message=r.error_message,
                    findings_referenced=set(r.findings_referenced),
                    paths_referenced=r.paths_referenced,
                )
        return None

    async def cancel_run(self, run_id: str, user_id: str) -> AgentRunCancelResponse:
        """Request immediate cancellation of an active run."""
        run = self._active_runs.get(run_id)
        if not run:
            return AgentRunCancelResponse(
                run_id=run_id,
                status="not_found",
                message=f"Run '{run_id}' not found.",
            )

        # Enforce user authorization on cancellation
        if run.user_id != user_id:
            return AgentRunCancelResponse(
                run_id=run_id,
                status="not_found",
                message=f"Run '{run_id}' does not belong to the authenticated user.",
            )

        if run.status in ("completed", "cancelled", "failed", "timeout", "step_limit_reached"):
            return AgentRunCancelResponse(
                run_id=run_id,
                status="already_terminal",
                message=f"Run '{run_id}' has already reached terminal status '{run.status}'.",
            )

        run.cancel_event.set()
        run.status = "cancelled"
        run.completed_at = int(datetime.now(timezone.utc).timestamp())
        self._persist_run(run)

        logger.info("Agent run '%s' marked for cancellation by user '%s'", run_id, user_id)
        return AgentRunCancelResponse(
            run_id=run_id,
            status="cancelled",
            message=f"Run '{run_id}' cancellation signal recorded.",
        )

    async def stream_investigation(
        self,
        project_id: str,
        message: str,
        user_id: str,
        user_email: str,
        run_id: str | None = None,
    ) -> AsyncIterator[str]:
        """Stream an agent investigation over Server-Sent Events."""
        effective_run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
        start_time = time.perf_counter()
        seq = 1

        run = RunContext(
            run_id=effective_run_id,
            project_id=project_id,
            user_id=user_id,
            user_email=user_email,
            status="accepted",
            prompt=message,
        )
        self._active_runs[effective_run_id] = run
        self._persist_run(run)

        step_limit = self.settings.AGENT_STEP_LIMIT
        timeout_seconds = self.settings.AGENT_RUN_TIMEOUT_SECONDS

        def make_event(event_name: str, payload: dict[str, Any]) -> str:
            nonlocal seq
            now = int(datetime.now(timezone.utc).timestamp())
            ev = AgentStreamEvent(
                event=event_name,
                run_id=effective_run_id,
                sequence=seq,
                timestamp=now,
                data=payload,
            )
            seq += 1
            return ev.to_sse()

        try:
            # 1. Emit run_started
            run.status = "running"
            self._persist_run(run)
            yield make_event(
                "run_started",
                {
                    "run_id": effective_run_id,
                    "project_id": project_id,
                    "step_limit": step_limit,
                    "timeout_seconds": timeout_seconds,
                    "user_email": user_email,
                },
            )

            # 2. Emit initial assistant status
            yield make_event(
                "assistant_status",
                {"status_text": "Analyzing investigation prompt and querying knowledge graph..."},
            )

            # 3. Autonomous Reasoning & Tool Loop
            # Hand-written deterministic graph investigation loop (No LangChain/LangGraph)
            cleaned_query = message.strip()
            query_lower = cleaned_query.lower()

            # Execute tool steps within budget and timeout
            async def execute_tool_step(
                tool_name: str,
                tool_inputs: dict[str, Any],
                display_label: str,
            ) -> ToolExecutionResponse | None:
                nonlocal seq
                # Check cancellation
                if run.cancel_event.is_set():
                    return None

                # Check timeout
                elapsed = time.perf_counter() - start_time
                if elapsed > timeout_seconds:
                    return None

                # Check step limit
                if run.step_count >= step_limit:
                    return None

                run.step_count += 1
                call_id = f"call-{uuid.uuid4().hex[:8]}"
                now_ts = int(datetime.now(timezone.utc).timestamp())

                # Persist initial tool call record
                tool_record = AgentToolCallRecord(
                    id=call_id,
                    run_id=effective_run_id,
                    sequence=run.step_count,
                    tool_name=tool_name,
                    display_name=display_label,
                    inputs=sanitize_tool_inputs(tool_inputs),
                    status="running",
                    started_at=now_ts,
                )
                self._persist_tool_call(tool_record)

                yield_ev = make_event(
                    "tool_started",
                    {
                        "tool_name": tool_name,
                        "call_id": call_id,
                        "display_name": display_label,
                        "inputs": tool_inputs,
                    },
                )
                yield_queue.append(yield_ev)

                # Execute through controlled tool executor
                result_resp = await self.executor.execute(
                    tool_name=tool_name,
                    arguments=tool_inputs,
                    actor_email=user_email,
                    is_admin=True,
                )

                duration_ms = result_resp.trace.duration_ms
                tool_record.status = "success" if result_resp.status == "success" else (
                    "rejected" if result_resp.status == "rejected" else "error"
                )
                tool_record.result_summary = result_resp.trace.result_summary
                tool_record.query_id = result_resp.trace.query_id
                tool_record.duration_ms = duration_ms
                tool_record.outcome = result_resp.trace.outcome
                tool_record.evidence_references = result_resp.trace.evidence_references
                tool_record.completed_at = int(datetime.now(timezone.utc).timestamp())
                tool_record.error_message = result_resp.error_message
                self._persist_tool_call(tool_record)

                yield_done_ev = make_event(
                    "tool_completed",
                    {
                        "tool_name": tool_name,
                        "call_id": call_id,
                        "status": result_resp.status,
                        "result_summary": result_resp.trace.result_summary,
                        "duration_ms": duration_ms,
                        "outcome": result_resp.trace.outcome,
                        "evidence_references": result_resp.trace.evidence_references,
                        "trace": result_resp.trace.model_dump(),
                    },
                )
                yield_queue.append(yield_done_ev)

                run.tool_calls.append({
                    "toolName": tool_name,
                    "callId": call_id,
                    "resultSummary": result_resp.trace.result_summary,
                    "durationMs": duration_ms,
                    "outcome": result_resp.trace.outcome,
                    "evidenceReferences": result_resp.trace.evidence_references,
                    "queryId": result_resp.trace.query_id,
                })
                self._persist_run(run)

                return result_resp

            yield_queue: list[str] = []

            # Determine investigation strategy from prompt
            wants_paths = any(w in query_lower for w in ("path", "reach", "exposure", "chain", "how", "direct", "transitive"))
            wants_ranking = any(w in query_lower for w in ("rank", "priorit", "highest", "critical", "top", "score"))
            wants_remediation = any(w in query_lower for w in ("fix", "upgrade", "remediat", "patch", "candidate"))
            wants_explanation = any(w in query_lower for w in ("explain", "why", "detail", "advisory", "evidence"))

            # Step 1: Always retrieve current project findings to ground context
            step1_resp = await execute_tool_step(
                "list_findings",
                {"project_id": project_id, "page": 1, "page_size": 25},
                "Querying project findings list",
            )
            for ev in yield_queue:
                yield ev
            yield_queue.clear()

            # Check early termination conditions
            if run.cancel_event.is_set():
                run.status = "cancelled"
                self._persist_run(run)
                yield make_event("run_cancelled", {"reason": "Run cancelled by user.", "step_count": run.step_count})
                return

            if time.perf_counter() - start_time > timeout_seconds:
                run.status = "timeout"
                self._persist_run(run)
                yield make_event("run_timeout", {"timeout_seconds": timeout_seconds, "message": "Run timed out."})
                return

            findings_data = step1_resp.data if step1_resp and step1_resp.status == "success" else None
            findings_items = findings_data.items if findings_data else []

            # Step 2: Ranking analysis if requested
            ranked_result = None
            if wants_ranking and not run.cancel_event.is_set() and run.step_count < step_limit:
                step2_resp = await execute_tool_step(
                    "rank_findings",
                    {"project_id": project_id, "limit": 20},
                    "Ranking findings with deterministic priority policy (v1.0.0)",
                )
                for ev in yield_queue:
                    yield ev
                yield_queue.clear()
                if step2_resp and step2_resp.status == "success":
                    ranked_result = step2_resp.data

            # Step 3: Targeted finding details & paths if relevant
            target_finding = None
            path_result = None
            explanation_result = None

            # Look for specific package mention or target top finding
            for f in findings_items:
                if f.package_name.lower() in query_lower or f.advisory_id.lower() in query_lower:
                    target_finding = f
                    break
            if not target_finding and findings_items:
                target_finding = findings_items[0]

            if target_finding:
                run.findings_referenced.add(target_finding.id)
                self._persist_run(run)

                if (wants_paths or wants_explanation) and not run.cancel_event.is_set() and run.step_count < step_limit:
                    # Fetch paths
                    path_resp = await execute_tool_step(
                        "get_dependency_paths",
                        {"project_id": project_id, "finding_id": target_finding.id, "max_depth": 8, "limit": 3},
                        f"Traversing graph paths to {target_finding.package_name}@{target_finding.package_version}",
                    )
                    for ev in yield_queue:
                        yield ev
                    yield_queue.clear()
                    if path_resp and path_resp.status == "success":
                        path_result = path_resp.data

                    # Fetch explanation
                    if not run.cancel_event.is_set() and run.step_count < step_limit:
                        exp_resp = await execute_tool_step(
                            "explain_finding",
                            {"project_id": project_id, "finding_id": target_finding.id},
                            f"Synthesizing exposure explanation for {target_finding.advisory_id}",
                        )
                        for ev in yield_queue:
                            yield ev
                        yield_queue.clear()
                        if exp_resp and exp_resp.status == "success":
                            explanation_result = exp_resp.data

            # Final check before answer generation
            if run.cancel_event.is_set():
                run.status = "cancelled"
                self._persist_run(run)
                yield make_event("run_cancelled", {"reason": "Run cancelled by user.", "step_count": run.step_count})
                return

            if time.perf_counter() - start_time > timeout_seconds:
                run.status = "timeout"
                self._persist_run(run)
                yield make_event("run_timeout", {"timeout_seconds": timeout_seconds, "message": "Run timed out."})
                return

            if run.step_count >= step_limit and wants_ranking and wants_paths:
                # Step limit reached
                run.status = "step_limit_reached"
                self._persist_run(run)
                yield make_event(
                    "run_step_limit",
                    {
                        "step_limit": step_limit,
                        "message": f"Execution halted after reaching maximum step budget of {step_limit} steps.",
                    },
                )
                return

            # 4. Synthesize Evidence-Backed Answer
            yield make_event("assistant_status", {"status_text": "Generating evidence-grounded response..."})

            answer_text = self._build_grounded_answer(
                query=cleaned_query,
                project_id=project_id,
                findings=findings_items,
                ranked_result=ranked_result,
                target_finding=target_finding,
                path_result=path_result,
                explanation_result=explanation_result,
                wants_paths=wants_paths,
                wants_ranking=wants_ranking,
                wants_remediation=wants_remediation,
            )

            # Stream answer incrementally in natural chunks
            words = answer_text.split(" ")
            chunk_size = 4
            for i in range(0, len(words), chunk_size):
                if run.cancel_event.is_set():
                    run.status = "cancelled"
                    self._persist_run(run)
                    yield make_event("run_cancelled", {"reason": "Run cancelled by user.", "step_count": run.step_count})
                    return

                chunk = " ".join(words[i : i + chunk_size])
                if i + chunk_size < len(words):
                    chunk += " "
                yield make_event("answer_delta", {"delta": chunk})
                await asyncio.sleep(0.02)  # Natural token-stream pacing

            # 5. Emit answer_completed
            path_summaries = [p.summary_text for p in path_result.paths] if path_result and path_result.paths else []
            run.paths_referenced.extend(path_summaries)
            run.final_answer = answer_text

            yield make_event(
                "answer_completed",
                {
                    "full_text": answer_text,
                    "findings_referenced": sorted(list(run.findings_referenced)),
                    "paths_referenced": path_summaries,
                },
            )

            # 6. Terminal event: run_completed
            total_duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            run.status = "completed"
            run.completed_at = int(datetime.now(timezone.utc).timestamp())
            self._persist_run(run)

            yield make_event(
                "run_completed",
                {
                    "run_id": effective_run_id,
                    "step_count": run.step_count,
                    "total_duration_ms": total_duration_ms,
                    "findings_count": len(run.findings_referenced),
                },
            )

        except asyncio.CancelledError:
            run.status = "cancelled"
            run.completed_at = int(datetime.now(timezone.utc).timestamp())
            self._persist_run(run)
            yield make_event("run_cancelled", {"reason": "Client disconnected or cancelled.", "step_count": run.step_count})
        except Exception as exc:
            logger.exception("Agent run '%s' failed unexpectedly: %s", effective_run_id, exc)
            run.status = "failed"
            run.error_message = str(exc)
            run.completed_at = int(datetime.now(timezone.utc).timestamp())
            self._persist_run(run)
            yield make_event(
                "run_failed",
                {
                    "error_code": "INTERNAL_AGENT_ERROR",
                    "error_message": f"Agent investigation error: {str(exc)}",
                },
            )
        finally:
            run.completed_at = run.completed_at or int(datetime.now(timezone.utc).timestamp())
            self._persist_run(run)
            logger.info(
                "Agent run '%s' finished with status='%s' in %d steps",
                effective_run_id,
                run.status,
                run.step_count,
            )

    def _build_grounded_answer(
        self,
        query: str,
        project_id: str,
        findings: list[Any],
        ranked_result: Any | None,
        target_finding: Any | None,
        path_result: Any | None,
        explanation_result: Any | None,
        wants_paths: bool,
        wants_ranking: bool,
        wants_remediation: bool,
    ) -> str:
        """Synthesize honest, evidence-grounded answer based strictly on real tool outputs."""
        if not findings:
            return (
                f"I investigated project `{project_id}` using `list_findings`, but no vulnerability findings "
                "were found matching the current project scope. "
                "Note: 'No findings' reflects currently imported service manifests and synchronized OSV advisories."
            )

        lines: list[str] = []

        # 1. Summary of findings
        lines.append(f"Based on the live graph investigation of project `{project_id}`:")

        # 2. Ranking breakdown if available
        if ranked_result:
            dist = ranked_result.distribution
            lines.append(
                f"\n### Priority Distribution (Policy {ranked_result.scoring_version})\n"
                f"- **Highest:** {dist.highest}\n"
                f"- **High:** {dist.high}\n"
                f"- **Medium:** {dist.medium}\n"
                f"- **Low:** {dist.low}\n"
            )

            top_ranked = ranked_result.ranked_findings[:3]
            if top_ranked:
                lines.append("Top ranked findings with deterministic priority reasons:")
                for rf in top_ranked:
                    reasons_str = "; ".join(rf.priority_reasons) if rf.priority_reasons else "Standard policy evaluation"
                    lines.append(
                        f"- [{rf.id}](/findings/{rf.id}) (**{rf.priority}** priority): `{rf.package_name}@{rf.package_version}` "
                        f"under `{rf.advisory_id}`. Reasons: {reasons_str}."
                    )

        # 3. Path and Exposure Analysis
        if target_finding:
            lines.append(f"\n### Architectural Exposure for Finding [{target_finding.id}](/findings/{target_finding.id})")
            lines.append(
                f"- **Advisory ID:** `{target_finding.advisory_id}` ({target_finding.severity} severity)\n"
                f"- **Package Version:** `{target_finding.package_name}@{target_finding.package_version}`\n"
                f"- **Service Scope:** `{target_finding.service_name}`"
            )

            if path_result:
                if path_result.has_path and path_result.paths:
                    shortest = path_result.paths[0]
                    kind = "Direct dependency" if shortest.is_direct else f"Transitive dependency ({shortest.depth} hops)"
                    lines.append(f"- **Exposure Chain ({kind}):** `{shortest.summary_text}`")
                elif path_result.no_path_message:
                    lines.append(f"- **Path Status:** {path_result.no_path_message}")
            elif target_finding.path_depth is not None:
                lines.append(f"- **Shortest Traversal Depth:** {target_finding.path_depth} hop(s)")

            if target_finding.fixed_version:
                lines.append(f"- **Remediation Target:** Upgrade to version `{target_finding.fixed_version}`.")
            else:
                lines.append("- **Remediation Status:** No official fixed version recorded in advisory metadata.")

        # 4. Remediation section if requested
        if wants_remediation:
            upgradeable = [f for f in findings if f.fixed_version]
            lines.append(f"\n### Remediation Overview\nFound **{len(upgradeable)}** finding(s) with known fixed versions:")
            for uf in upgradeable[:4]:
                lines.append(
                    f"- **{uf.package_name}**: Upgrade from `{uf.package_version}` to `{uf.fixed_version}` to address [{uf.id}](/findings/{uf.id})."
                )

        # 5. Non-exploitability safety caveat
        lines.append(
            "\n*Notice: Vulnify reports architectural exposure based on static dependency graphs and service manifests, "
            "not proof of runtime exploitability. Absence of a path does not guarantee safety.*"
        )

        return "\n".join(lines)


# Singleton orchestrator provider
_orchestrator: AgentOrchestrator | None = None


def get_agent_orchestrator() -> AgentOrchestrator:
    """Retrieve or lazily initialize the singleton agent orchestrator."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator()
    return _orchestrator


def set_agent_orchestrator(orchestrator: AgentOrchestrator | None) -> None:
    """Override singleton agent orchestrator (for testing)."""
    global _orchestrator
    _orchestrator = orchestrator

