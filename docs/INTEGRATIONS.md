# Vulnify — Integrations Guide

> **External APIs, Ecosystem Adapters, Model Context Protocol (FastMCP), and LLM Providers**  
> *Authoritative specifications for connecting Vulnify to OSV.dev, GitHub REST APIs, and AI inference backends.*

---

## 1. Open Source Vulnerabilities (OSV) Integration

Vulnify integrates with [OSV.dev](https://osv.dev) to continuously ingest vulnerability advisories across open-source ecosystems.

### 1.1 Ingestion Flow & Endpoints
- **Batch Query Endpoint**: `POST https://api.osv.dev/v1/querybatch`
- **Single Advisory Endpoint**: `GET https://api.osv.dev/v1/vulns/{advisory_id}`
- **Protocol**: Asynchronous HTTP/1.1 and HTTP/2 via `httpx.AsyncClient`.

### 1.2 Ecosystem Mapping

| Vulnify Ecosystem | OSV Ecosystem Target | Version Standard Evaluated |
| :--- | :--- | :--- |
| `npm` | `npm` | Semantic Versioning (`semver` v3.0+) |
| `python` | `PyPI` | PEP 440 (`packaging.version` v24.0+) |
| `cargo` | `crates.io` | Cargo SemVer (`semver` v3.0+) |
| `golang` | `Go` | Semantic Versioning (`vX.Y.Z`) |

---

### 1.3 Local Disk Caching & Rate Limiting
To prevent hitting OSV API rate limits and ensure offline resilience:
- **Cache Location**: `backend/.osv_cache/`
- **Cache Format**: JSON files partitioned by ecosystem: `backend/.osv_cache/{ecosystem}/{package_name}.json`.
- **TTL**: Configured via `OSV_CACHE_TTL_SECONDS` (default: `86400` seconds / 24 hours).
- **Concurrency Limiting**: Managed via `asyncio.Semaphore(OSV_MAX_CONCURRENT_REQUESTS)` (default: 5 concurrent outbound connections).
- **Exponential Backoff**: In case of HTTP 429 or 5xx responses, retries up to `OSV_API_MAX_RETRIES` (default: 3) with backoff formula:  
  $$\text{delay} = \text{OSV\_API\_BACKOFF\_BASE\_SECONDS} \times 2^{\text{attempt}}$$

---

## 2. GitHub REST API Integration

Vulnify bridges security findings directly to engineering remediation workflows by opening structured GitHub issues in the user's repository.

### 2.1 Configuration & Token Management
GitHub integration can be configured centrally via environment variables or through the Admin UI:
- **Environment Configuration**:
  - `GITHUB_TOKEN`: Fine-grained Personal Access Token (PAT) with `Issues: Read and write` permission.
  - `GITHUB_DEFAULT_OWNER`: Organization or username (default: `vulnify`).
  - `GITHUB_DEFAULT_REPO`: Repository name (default: `demo-workspace`).
  - `GITHUB_API_BASE_URL`: `https://api.github.com`
  - `GITHUB_API_VERSION`: `2022-11-28`
- **Database Storage**: Admin-configured tokens are stored encrypted in FalkorDB under `(:GitHubConfig)` nodes.

---

### 2.2 Human-in-the-Loop Cryptographic Gating

To prevent unauthorized, hallucinated, or automated issue creation, Vulnify mandates a cryptographic handshake:

```
[User clicks 'Preview Fix Issue']
       |
       v
[Backend generates remediation plan JSON]
       |
       v
[Backend computes SHA-256 hash: plan_hash]
       |
       v
[Frontend renders preview modal with plan_hash]
       |
       v
[User reviews plan and clicks 'Approve & Open Issue']
       |
       v
[Frontend sends POST /issues with { plan_hash, approved: true }]
       |
       v
[Backend recomputes hash from current state]
       |
     /   \
  Matches?  No  --> [409 Conflict: Plan modified or stale]
    /
   Yes
  /
[Dispatches POST https://api.github.com/repos/{owner}/{repo}/issues]
       |
       v
[201 Created: Issue #42 link returned to user]
```

### 2.3 Generated Issue Format
Issues created by Vulnify contain rich architectural evidence:
```markdown
## Security Remediation: Upgrade lodash to 4.17.21

### Vulnerability Summary
- **Advisory ID**: GHSA-p6mc-m468-83gw (CVE-2019-10744)
- **Severity**: HIGH (CVSS 7.4)
- **Affected Version**: `lodash@4.17.15`
- **Recommended Target**: `lodash@4.17.21` (safe patch candidate)

### Architectural Exposure Evidence
The vulnerable package is reachable from public-facing services:
`api-gateway` -> `express@4.18.2` -> `lodash@4.17.15` (depth 2)

### Upgrade Blast Radius Analysis
- **Services using this package**: `api-gateway`, `auth-service`
- **Breaking changes detected**: None (patch release)

*Opened automatically by Vulnify after explicit human review and authorization.*
```

---

## 3. FastMCP (Model Context Protocol) Integration

Vulnify implements the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) using `mcp>=2.3.0`.

### 3.1 Architecture
Rather than duplicating tool definitions between internal REST routers and the AI agent, Vulnify defines all analytical capabilities as FastMCP tools in `backend/src/vulnify/agent/tools/`.

```
                    +------------------------------------+
                    |        FastMCP Tool Registry       |
                    |   (backend/src/vulnify/agent/)     |
                    +-----------------+------------------+
                                      |
         +----------------------------+----------------------------+
         |                                                         |
         v                                                         v
+-------------------------------+                         +-------------------------------+
|     AI Agent Orchestrator     |                         |    External MCP Clients       |
|  (In-App Streaming SSE Run)   |                         |   (Claude Desktop, AGY, etc.) |
+-------------------------------+                         +-------------------------------+
```

### 3.2 Tool Inventory

| Tool Name | Type | Access Level | Description |
| :--- | :--- | :--- | :--- |
| `list_findings` | Read | Safe | Lists unreviewed findings for a project. |
| `get_finding_details` | Read | Safe | Fetches advisory metadata, CVSS vector, and affected ranges. |
| `get_dependency_paths`| Read | Safe | Executes bounded Cypher traversal returning shortest dependency paths. |
| `rank_findings` | Read | Safe | Calculates deterministic priority bands (P0-P3) with explainable reasons. |
| `explain_finding` | Read | Safe | Generates contextual analysis combining graph paths and advisory text. |
| `record_decision` | Write| Gated | Records human analyst triage status on a finding. |
| `open_fix_issue` | Write| **Cryptographic Gate** | Previews or dispatches remediation issues to GitHub. |

---

## 4. LLM Provider Integration

Vulnify supports multiple LLM inference providers via an abstraction layer in `backend/src/vulnify/agent/orchestrator.py`:

### 4.1 Mistral AI (Default)
- **Default Model**: `mistral-small-latest` (or `mistral-large-latest`)
- **API Endpoint**: `https://api.mistral.ai/v1/chat/completions`
- **Configuration**: `MISTRAL_API_KEY` in `backend/.env`.

### 4.2 OpenAI (Optional)
- **Model**: `gpt-4o-mini` or `gpt-4o`
- **API Endpoint**: `https://api.openai.com/v1/chat/completions`
- **Configuration**: Set `AGENT_LLM_PROVIDER=openai` and `OPENAI_API_KEY` in `backend/.env`.

### 4.3 Google Gemini (Optional)
- **Model**: `gemini-1.5-pro` or `gemini-2.0-flash`
- **API Endpoint**: Google Generative AI REST API.
- **Configuration**: Set `AGENT_LLM_PROVIDER=gemini` and `GEMINI_API_KEY` in `backend/.env`.

---

## 5. Agent Operational Boundaries

To ensure predictability and prevent runaway API expenses:
- **`AGENT_STEP_LIMIT`**: Defaults to 10 iterations (hard capped at 30).
- **`AGENT_RUN_TIMEOUT_SECONDS`**: Defaults to 60 seconds (hard capped at 300s).
- **Streaming Over SSE**: Real-time event emission enables the client to cancel long-running investigations immediately.
- **Untrusted Context Handling**: Advisory descriptions and package metadata are passed to LLMs strictly as quoted data blocks, preventing prompt injection attacks.
