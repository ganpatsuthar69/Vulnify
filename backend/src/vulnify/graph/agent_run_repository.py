"""Repository for persisting and querying AgentRun and AgentToolCall entities in FalkorDB (US-603).

Responsibilities:
1. Durable persistence of every agent reasoning session, user prompt, and lifecycle state.
2. Ordered audit trail of all intermediate tool invocations with parameterized inputs and result summaries.
3. Retention of catalog query identifiers, execution latency, and primary evidence references.
4. Input sanitization preventing sensitive credentials/tokens from entering stored traces.
5. In-memory implementation for isolated unit testing and mock mode.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
from typing import Any, Protocol

from vulnify.graph.client import GraphClient, get_graph_client, load_query

logger = logging.getLogger("vulnify")

SENSITIVE_KEY_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "cookie",
    "key",
    "auth",
    "credentials",
    "authorization",
)


def sanitize_tool_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    """Recursively scrub known sensitive parameter names from tool invocation inputs."""
    if not isinstance(inputs, dict):
        return inputs

    sanitized: dict[str, Any] = {}
    for k, v in inputs.items():
        k_lower = str(k).lower()
        if any(sub in k_lower for sub in SENSITIVE_KEY_SUBSTRINGS):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_tool_inputs(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_tool_inputs(item) if isinstance(item, dict) else item for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


@dataclass
class AgentRunRecord:
    """Durable record of an agent investigation run."""

    id: str
    project_id: str
    user_id: str
    user_email: str
    prompt: str
    status: str
    started_at: int
    completed_at: int | None = None
    final_answer: str | None = None
    error_message: str | None = None
    step_count: int = 0
    findings_referenced: list[str] = field(default_factory=list)
    paths_referenced: list[str] = field(default_factory=list)
    tool_call_count: int = 0


@dataclass
class AgentToolCallRecord:
    """Durable record of a single tool invocation within an agent run."""

    id: str
    run_id: str
    sequence: int
    tool_name: str
    display_name: str | None = None
    inputs: dict[str, Any] = field(default_factory=dict)
    result_summary: str = ""
    status: str = "running"  # running, success, error, rejected
    query_id: str | None = None
    duration_ms: float | None = None
    outcome: str | None = None
    evidence_references: list[str] = field(default_factory=list)
    started_at: int = 0
    completed_at: int | None = None
    error_message: str | None = None


class IAgentRunRepository(Protocol):
    """Protocol for AgentRun and AgentToolCall persistence and trace retrieval."""

    def upsert_run(self, run: AgentRunRecord) -> AgentRunRecord: ...
    def get_run(self, project_id: str, run_id: str) -> AgentRunRecord | None: ...
    def get_run_by_id(self, run_id: str) -> AgentRunRecord | None: ...
    def list_runs(
        self,
        project_id: str,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[AgentRunRecord], int]: ...
    def upsert_tool_call(self, tool_call: AgentToolCallRecord) -> AgentToolCallRecord: ...
    def get_run_tool_calls(self, run_id: str) -> list[AgentToolCallRecord]: ...
    def get_runs_by_finding(
        self,
        project_id: str,
        finding_id: str,
        limit: int = 10,
    ) -> list[AgentRunRecord]: ...


class FalkorAgentRunRepository:
    """FalkorDB graph database implementation of IAgentRunRepository."""

    def __init__(self, client: GraphClient | None = None) -> None:
        self.client = client or get_graph_client()
        self._query_upsert_run = load_query("upsert_agent_run.cypher")
        self._query_get_run = load_query("get_agent_run.cypher")
        self._query_list_runs = load_query("list_agent_runs.cypher")
        self._query_count_runs = load_query("count_agent_runs.cypher")
        self._query_upsert_tool_call = load_query("upsert_agent_tool_call.cypher")
        self._query_get_run_tool_calls = load_query("get_run_tool_calls.cypher")
        self._query_get_runs_by_finding = load_query("get_agent_runs_by_finding.cypher")

    def _row_to_run(self, row: list[Any]) -> AgentRunRecord:
        findings_raw = row[11]
        paths_raw = row[12]
        findings = json.loads(findings_raw) if findings_raw and isinstance(findings_raw, str) else (findings_raw or [])
        paths = json.loads(paths_raw) if paths_raw and isinstance(paths_raw, str) else (paths_raw or [])

        return AgentRunRecord(
            id=str(row[0]),
            project_id=str(row[1]),
            user_id=str(row[2]),
            user_email=str(row[3]),
            prompt=str(row[4]),
            status=str(row[5]),
            started_at=int(row[6]),
            completed_at=int(row[7]) if row[7] is not None else None,
            final_answer=str(row[8]) if row[8] is not None else None,
            error_message=str(row[9]) if row[9] is not None else None,
            step_count=int(row[10]) if row[10] is not None else 0,
            findings_referenced=findings,
            paths_referenced=paths,
            tool_call_count=int(row[13]) if row[13] is not None else 0,
        )

    def _row_to_tool_call(self, row: list[Any]) -> AgentToolCallRecord:
        inputs_raw = row[5]
        evidence_raw = row[11]
        inputs = json.loads(inputs_raw) if inputs_raw and isinstance(inputs_raw, str) else (inputs_raw or {})
        evidence = json.loads(evidence_raw) if evidence_raw and isinstance(evidence_raw, str) else (evidence_raw or [])

        return AgentToolCallRecord(
            id=str(row[0]),
            run_id=str(row[1]),
            sequence=int(row[2]),
            tool_name=str(row[3]),
            display_name=str(row[4]) if row[4] is not None else None,
            inputs=inputs,
            result_summary=str(row[6]) if row[6] is not None else "",
            status=str(row[7]),
            query_id=str(row[8]) if row[8] is not None else None,
            duration_ms=float(row[9]) if row[9] is not None else None,
            outcome=str(row[10]) if row[10] is not None else None,
            evidence_references=evidence,
            started_at=int(row[12]),
            completed_at=int(row[13]) if row[13] is not None else None,
            error_message=str(row[14]) if row[14] is not None else None,
        )

    def upsert_run(self, run: AgentRunRecord) -> AgentRunRecord:
        graph = self.client.get_graph()
        params = {
            "id": run.id,
            "project_id": run.project_id,
            "user_id": run.user_id,
            "user_email": run.user_email,
            "prompt": run.prompt,
            "status": run.status,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "final_answer": run.final_answer,
            "error_message": run.error_message,
            "step_count": run.step_count,
            "findings_referenced_json": json.dumps(run.findings_referenced),
            "paths_referenced_json": json.dumps(run.paths_referenced),
            "tool_call_count": run.tool_call_count,
        }
        graph.query(self._query_upsert_run, params)
        return run

    def get_run(self, project_id: str, run_id: str) -> AgentRunRecord | None:
        graph = self.client.get_graph()
        result = graph.query(self._query_get_run, {"project_id": project_id, "run_id": run_id})
        if not result.result_set:
            return None
        return self._row_to_run(result.result_set[0])

    def get_run_by_id(self, run_id: str) -> AgentRunRecord | None:
        graph = self.client.get_graph()
        query = (
            "MATCH (p:Project)-[:HAS_AGENT_RUN]->(r:AgentRun {id: $run_id}) "
            "RETURN r.id, r.project_id, r.user_id, r.user_email, r.prompt, r.status, "
            "r.started_at, r.completed_at, r.final_answer, r.error_message, r.step_count, "
            "r.findings_referenced_json, r.paths_referenced_json, r.tool_call_count"
        )
        result = graph.query(query, {"run_id": run_id})
        if not result.result_set:
            return None
        return self._row_to_run(result.result_set[0])

    def list_runs(
        self,
        project_id: str,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[AgentRunRecord], int]:
        graph = self.client.get_graph()
        count_res = graph.query(self._query_count_runs, {"project_id": project_id})
        total = int(count_res.result_set[0][0]) if count_res.result_set else 0

        list_res = graph.query(
            self._query_list_runs,
            {"project_id": project_id, "limit": limit, "offset": offset},
        )
        runs = [self._row_to_run(row) for row in list_res.result_set]
        return runs, total

    def upsert_tool_call(self, tool_call: AgentToolCallRecord) -> AgentToolCallRecord:
        graph = self.client.get_graph()
        params = {
            "id": tool_call.id,
            "run_id": tool_call.run_id,
            "sequence": tool_call.sequence,
            "tool_name": tool_call.tool_name,
            "display_name": tool_call.display_name,
            "inputs_json": json.dumps(sanitize_tool_inputs(tool_call.inputs)),
            "result_summary": tool_call.result_summary,
            "status": tool_call.status,
            "query_id": tool_call.query_id,
            "duration_ms": tool_call.duration_ms,
            "outcome": tool_call.outcome,
            "evidence_references_json": json.dumps(tool_call.evidence_references),
            "started_at": tool_call.started_at,
            "completed_at": tool_call.completed_at,
            "error_message": tool_call.error_message,
        }
        graph.query(self._query_upsert_tool_call, params)
        return tool_call

    def get_run_tool_calls(self, run_id: str) -> list[AgentToolCallRecord]:
        graph = self.client.get_graph()
        result = graph.query(self._query_get_run_tool_calls, {"run_id": run_id})
        return [self._row_to_tool_call(row) for row in result.result_set]

    def get_runs_by_finding(
        self,
        project_id: str,
        finding_id: str,
        limit: int = 10,
    ) -> list[AgentRunRecord]:
        graph = self.client.get_graph()
        result = graph.query(
            self._query_get_runs_by_finding,
            {"project_id": project_id, "finding_id": finding_id, "limit": limit},
        )
        return [self._row_to_run(row) for row in result.result_set]


class InMemoryAgentRunRepository:
    """In-memory implementation for isolated unit testing and mock mode."""

    def __init__(self) -> None:
        self._runs: dict[str, AgentRunRecord] = {}
        self._tool_calls: dict[str, list[AgentToolCallRecord]] = {}

    def upsert_run(self, run: AgentRunRecord) -> AgentRunRecord:
        # Preserve existing tool call count if not provided
        if run.id in self._tool_calls:
            run.tool_call_count = len(self._tool_calls[run.id])
        self._runs[run.id] = run
        return run

    def get_run(self, project_id: str, run_id: str) -> AgentRunRecord | None:
        run = self._runs.get(run_id)
        if run and run.project_id == project_id:
            return run
        return None

    def get_run_by_id(self, run_id: str) -> AgentRunRecord | None:
        return self._runs.get(run_id)

    def list_runs(
        self,
        project_id: str,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[AgentRunRecord], int]:
        matching = [r for r in self._runs.values() if r.project_id == project_id]
        matching.sort(key=lambda r: r.started_at, reverse=True)
        total = len(matching)
        paginated = matching[offset : offset + limit]
        return paginated, total

    def upsert_tool_call(self, tool_call: AgentToolCallRecord) -> AgentToolCallRecord:
        # Redact inputs before persistence
        tool_call.inputs = sanitize_tool_inputs(tool_call.inputs)
        calls = self._tool_calls.setdefault(tool_call.run_id, [])
        # Update in-place if existing id, else append
        idx = next((i for i, c in enumerate(calls) if c.id == tool_call.id), None)
        if idx is not None:
            calls[idx] = tool_call
        else:
            calls.append(tool_call)
        calls.sort(key=lambda c: c.sequence)

        # Update parent run tool_call_count
        if tool_call.run_id in self._runs:
            self._runs[tool_call.run_id].tool_call_count = len(calls)

        return tool_call

    def get_run_tool_calls(self, run_id: str) -> list[AgentToolCallRecord]:
        calls = self._tool_calls.get(run_id, [])
        return sorted(calls, key=lambda c: c.sequence)

    def get_runs_by_finding(
        self,
        project_id: str,
        finding_id: str,
        limit: int = 10,
    ) -> list[AgentRunRecord]:
        matching = [
            r for r in self._runs.values()
            if r.project_id == project_id and finding_id in r.findings_referenced
        ]
        matching.sort(key=lambda r: r.started_at, reverse=True)
        return matching[:limit]

    def clear(self) -> None:
        self._runs.clear()
        self._tool_calls.clear()


# Default provider function and test override hook
_repository_override: IAgentRunRepository | None = None


def get_agent_run_repository() -> IAgentRunRepository:
    """FastAPI dependency for accessing the configured AgentRun repository."""
    if _repository_override is not None:
        return _repository_override
    return FalkorAgentRunRepository()


def set_agent_run_repository_override(repo: IAgentRunRepository | None) -> None:
    """Override repository singleton (used in test fixtures)."""
    global _repository_override
    _repository_override = repo
