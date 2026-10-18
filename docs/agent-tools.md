# Vulnify Agent Tools & MCP Server Architecture (US-601)

Vulnify provides a graph-powered security investigation agent built around an authoritative **Tool Registry**, a **Controlled Execution Layer**, and a **Model Context Protocol (MCP)** server.

---

## 1. Core Architectural Principles

1. **Single Source of Truth**: Every tool is defined once in the central `ToolRegistry` (`backend/src/vulnify/agent/registry.py`) with typed Pydantic input/output schemas. The same registry powers both the FastAPI discovery endpoints and the FastMCP server.
2. **One File Per Tool**: Each tool resides in its own isolated module under `backend/src/vulnify/agent/tools/`.
3. **Strict Query Parameterization**: The agent **never** writes raw Cypher queries, dynamically concatenates query strings, or executes shell commands. Every tool wraps a fixed, parameterized Cypher query or backend domain service.
4. **Read-Only by Default & Approval Gating**: All query and analysis tools are read-only. State-mutating tools (`record_decision` and `open_fix_issue`) are explicitly classified as `write_gated` and require verified human approval (`confirmed: true`) before mutating any database or external state.
5. **Execution Provenance & Trace Fragments**: Every tool invocation produces structured data accompanied by a `TraceFragment` recording tool version, query ID, inputs, duration, evaluated timestamp, and an honest outcome classification (`success`, `no_path`, `empty`, `rejected`, `error`).
6. **Honest Safety & Non-Exploitability**: Vulnify reports architectural exposure based on static dependency chains and service manifests. Vulnify tools never claim a finding is "exploitable" or that absence of a path guarantees safety.

---

## 2. Trace Fragment Contract

Every tool execution returns a standardized `TraceFragment` (`backend/src/vulnify/agent/schemas.py`):

```json
{
  "tool_name": "get_dependency_paths",
  "tool_version": "1.0.0",
  "query_id": "get_project_finding_paths",
  "inputs": {
    "project_id": "proj-ecommerce",
    "finding_id": "find-a1b2c3d4",
    "max_depth": 8,
    "limit": 5
  },
  "result_summary": "Found 1 path(s) (shortest depth: 2) from service 'checkout-api' to lodash@4.17.20 [transitive (depth 2)].",
  "duration_ms": 14.85,
  "record_count": 1,
  "evaluated_at": 1729267200,
  "outcome": "success",
  "evidence_references": ["GHSA-35jh-r3h4-6jhm"],
  "warning": null
}
```

### Outcome Classifications
- `success`: Query or operation succeeded and returned evidence records.
- `no_path`: Path traversal completed bounded search; no path exists within evaluated depth.
- `empty`: Query executed successfully but matching entity/record does not exist.
- `rejected`: Operation blocked by human gating policy (e.g. unconfirmed write attempt).
- `error`: Upstream database or external API failure occurred.

---

## 3. Tool Catalog

### 3.1. `list_findings`
- **Classification**: `read_only`
- **Underlying Query**: `get_project_findings` (`get_project_findings.cypher`)
- **Requires Approval**: `False`
- **Purpose**: Retrieves paginated, project-scoped vulnerability findings with server-side filtering by service, priority band, triage status, and search query.
- **Inputs**:
  - `project_id` (str, required): Unique project identifier.
  - `service_id` (str, optional): Scope to a specific service.
  - `priority` (str, optional): Filter by priority (`Highest`, `High`, `Medium`, `Low`).
  - `status` (str, optional): Filter by triage status (`open`, `affected`, `not_affected`, `fixed`).
  - `search` (str, optional): Search term for package name or advisory ID.
  - `page` (int, default `1`): 1-indexed page number.
  - `page_size` (int, default `25`, max `100`): Results per page.
- **Outputs**: `ListFindingsResult` containing `items` (list of `FindingSummaryItem`), `total`, `page`, `page_size`, and `trace`.

---

### 3.2. `get_finding_details`
- **Classification**: `read_only`
- **Underlying Query**: `get_project_finding_detail` (`get_project_finding_detail.cypher`)
- **Requires Approval**: `False`
- **Purpose**: Retrieves complete evidence for a single finding, including version matching justification (`reason_code`, `matched_range`), advisory description, fixed versions, aliases, and scoring criteria.
- **Inputs**:
  - `project_id` (str, required): Unique project identifier.
  - `finding_id` (str, required): Finding hash identifier (`find-...`) or advisory ID (`GHSA-...`, `OSV-...`).
- **Outputs**: `GetFindingDetailsResult` containing `found` (bool), `finding` (`FindingDetailItem` or `None`), and `trace`.

---

### 3.3. `get_dependency_paths`
- **Classification**: `read_only`
- **Underlying Query**: `get_project_finding_paths` (`get_project_finding_paths.cypher`)
- **Requires Approval**: `False`
- **Purpose**: Traverses the dependency graph from the root service entrypoint to the vulnerable package version, returning intermediate nodes, edges, provenance, and depth.
- **Inputs**:
  - `project_id` (str, required): Unique project identifier.
  - `finding_id` (str, required): Finding or advisory identifier.
  - `max_depth` (int, default `8`, bounds `1..15`): Maximum traversal depth.
  - `limit` (int, default `5`, bounds `1..20`): Maximum shortest paths to return.
- **Outputs**: `GetDependencyPathsResult` containing `has_path`, `paths` (list of `DependencyPathItem` with `nodes` and `edges`), `total_found`, `is_truncated`, `no_path_message`, and `trace`.
- **Honesty Guarantee**: If `has_path` is false, returns explicit `no_path_message` and warning stating that absence of a path within depth bounds does not guarantee absence of exposure.

---

### 3.4. `explain_finding`
- **Classification**: `read_only`
- **Underlying Query**: `explain_finding_synthesis` (synthesizes `get_project_finding_detail` and `get_project_finding_paths`)
- **Requires Approval**: `False`
- **Purpose**: Synthesizes graph exposure evidence, reachability depth, advisory details, and remediation status into an objective architectural summary.
- **Inputs**:
  - `project_id` (str, required): Unique project identifier.
  - `finding_id` (str, required): Finding or advisory identifier.
- **Outputs**: `ExplainFindingResult` containing `found`, `explanation` (`ExposureExplanation`), `summary_text`, and `trace`.
- **Safety Guarantee**: Adheres strictly to non-exploitability rules; explicitly describes architectural exposure rather than claiming runtime exploitability.

---

### 3.5. `rank_findings`
- **Classification**: `read_only`
- **Underlying Engine**: `rank_project_findings` (`vulnify.scoring.engine`, version `v1.0.0`)
- **Requires Approval**: `False`
- **Purpose**: Ranks and groups vulnerability findings using Vulnify's deterministic priority policy (`v1.0.0`), computing priority distributions and strict tie-broken ordering.
- **Inputs**:
  - `project_id` (str, required): Unique project identifier.
  - `service_id` (str, optional): Service scope filter.
  - `limit` (int, default `50`, bounds `1..200`): Maximum ranked findings.
- **Outputs**: `RankFindingsResult` containing `scoring_version` ("v1.0.0"), `distribution` (counts for Highest, High, Medium, Low, Unknown), `ranked_findings`, and `trace`.

---

### 3.6. `record_decision`
- **Classification**: `write_gated`
- **Underlying Query**: `record_triage_decision` (`record_triage_decision.cypher`)
- **Requires Approval**: `True`
- **Purpose**: Records an explicit human-approved triage decision (`open`, `affected`, `not_affected`, `fixed`) on the graph relationship.
- **Inputs**:
  - `project_id` (str, required): Unique project identifier.
  - `finding_id` (str, required): Target finding identifier.
  - `status` (Literal["open", "affected", "not_affected", "fixed"], required): Target triage status.
  - `justification` (str, optional): Mandatory explanation (>= 10 characters) when marking `not_affected`.
  - `triaged_by` (str, default `"agent"`): Identity of operator recording the decision.
  - `confirmed` (bool, default `False`): **Explicit human approval confirmation.**
- **Outputs**: `RecordDecisionResult` containing `success`, previous and new status, justification, timestamp, and `trace`.
- **Gating Enforcement**: If `confirmed` is `False`, execution is rejected without mutating the graph.

---

### 3.7. `open_fix_issue`
- **Classification**: `write_gated`
- **Underlying Service**: `open_github_issue` (`GitHubService.create_issue`)
- **Requires Approval**: `True`
- **Purpose**: Creates a real GitHub issue for an approved remediation plan in the team-owned repository.
- **Inputs**:
  - `project_id` (str, required): Unique project identifier.
  - `finding_id` (str, required): Finding identifier.
  - `target_repo` (str, optional): Target repository; must match configured team repository.
  - `title` (str, optional): Custom issue title; defaults to standard Vulnify template.
  - `body` (str, optional): Markdown issue description with graph evidence.
  - `plan_hash` (str, optional): Cryptographic SHA-256 plan hash from preview.
  - `confirmed` (bool, default `False`): **Explicit human approval confirmation.**
- **Outputs**: `OpenFixIssueResult` containing `issue_number`, `issue_url`, `target_repo`, `plan_hash`, `status`, and `trace`.
- **Gating Enforcement**: Fails closed if unconfirmed. Re-submitting the same plan hash returns the existing issue idempotently.

---

## 4. MCP Server Integration

Vulnify exposes the tools directly over the **Model Context Protocol** (`backend/src/vulnify/agent/mcp_server.py`):

```python
from vulnify.agent.mcp_server import create_mcp_server

# Create MCP server with all registered tools
server = create_mcp_server()

# List tools dynamically
tools = await server.list_tools()

# Execute tool via standard MCP protocol
result = await server.call_tool("list_findings", {"project_id": "proj-123"})
```

### Transports Supported
- **SSE (Server-Sent Events)**: Streamable HTTP transport for remote agent interactions (`server.sse_app`).
- **stdio**: Standard input/output transport for command-line LLM runners (`server.run_stdio_async()`).

---

## 5. REST API Endpoints

Agent capabilities can also be discovered and executed via Vulnify's HTTP API:

- `GET /api/agent/tools`: Dynamic capability discovery returning all registered tools and JSON schemas.
- `GET /api/agent/tools/{tool_name}`: Inspect parameters and approval requirements for a single tool.
- `POST /api/agent/tools/{tool_name}/execute`: Execute tool with input payload. Requires session authentication and CSRF token (`X-Requested-With: vulnify`). Gated write tools require `"confirmed": true` in the arguments.
