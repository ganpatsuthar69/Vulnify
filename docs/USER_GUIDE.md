# Vulnify — End-User Guide & Platform Workflows

> **Step-by-Step Operator Guide for Security Engineers, Architects, and Developers**  
> *A comprehensive walkthrough of core workflows, interface screens, and remediation processes.*

---

## 1. Getting Started: Authentication & Projects

### 1.1 Account Registration & Login
1. Open your browser and navigate to `http://localhost:5173`.
2. If this is your first visit, click **Create an account** on the login screen (`/register`).
3. Enter your full name, work email address, and a secure password (minimum 8 characters).
4. Upon successful registration, you will be automatically authenticated via a secure session cookie and redirected to the main dashboard.

---

### 1.2 Managing Projects & Workspaces
Vulnify organizes security intelligence by **Projects** (representing applications, microservice clusters, or repository groups).

```
+-------------------------------------------------------------------+
|  [Vulnify Logo]  | Active Project: [ E-Commerce Core v ]  | User  |
+-------------------------------------------------------------------+
```

- **Switching Projects**: Click the project dropdown in the top navigation header (`ProjectSelector.tsx`) to switch between workspaces.
- **Creating a Project**: Click **+ New Project** in the project dropdown or navigate to `/projects/new`. Specify:
  - **Project Name**: e.g., `Payment Gateway Service`
  - **Description**: e.g., `PCI-compliant card processing services`
  - **Ecosystem**: Select dominant ecosystem (`npm`, `python`, `cargo`, `go`, or `multi`).

---

## 2. Ingesting Dependencies

To analyze exposure paths, you must first import your application's dependency tree.

### 2.1 Uploading Lockfiles (`/import`)
1. In the sidebar, navigate to **Import Data**.
2. Fill in the service context:
   - **Service Name**: Identifier for the microservice (e.g., `auth-service` or `api-gateway`).
   - **Environment**: Choose `Production` or `Development`.
   - **Public Facing**: Check this box if the service directly accepts external Internet traffic (critical for P0 priority scoring).
3. **Select Lockfile**: Drag and drop or browse for your manifest file:
   - JavaScript / TypeScript: `package-lock.json` (npm)
   - Python: `requirements.txt`, `Pipfile.lock`, or `poetry.lock`
   - Rust: `Cargo.lock`
   - Go: `go.mod` / `go.sum`
4. Click **Parse & Ingest Graph**.

```
[ Upload Lockfile ]
  |--> Content Hash Deduplication (SHA-256)
  |--> FalkorDB Batch Upsert (UNWIND)
  |--> Live OSV Query & Match
  |--> Graph Nodes & Edges Persisted
```

5. Once ingestion completes, a summary card displays the number of packages parsed, dependency edges created, and advisories matched.

### 2.2 Reviewing Ingestion History (`/import/history`)
Navigate to **Ingestion History** to inspect an immutable audit log of all imports, including timestamps, file digests, and package counts.

---

## 3. Interactive Graph Explorer (`/explorer`)

The **Graph Explorer** provides a visual representation of your architecture powered by `@xyflow/react`.

```
        +-----------------------+
        |  (S) api-gateway      | [Public]
        +-----------+-----------+
                    | :DEPENDS_ON
                    v
        +-----------------------+
        |  (P) express@4.18.2   |
        +-----------+-----------+
                    | :DEPENDS_ON
                    v
        +-----------------------+       :AFFECTS       +-----------------------+
        |  (P) lodash@4.17.15   | <------------------- | (V) GHSA-p6mc-m468... | [HIGH]
        +-----------------------+                      +-----------------------+
```

### Key Explorer Capabilities:
- **Navigation**: Click and drag to pan across the canvas; use the mouse wheel or on-screen controls to zoom.
- **Node Filtering**: Use the sidebar filter pills to toggle visibility of Services, Package Versions, or Vulnerability Advisories.
- **Path Highlighting**: Clicking any vulnerable package or advisory automatically illuminates all upstream paths leading back to entry services.
- **Node Inspector Drawer**: Clicking an individual node opens a right-hand drawer displaying exact versions, licenses, PURL strings, and linked CVE records.

---

## 4. Findings & Deterministic Risk Prioritization (`/priorities`)

Traditional scanners overwhelm teams with hundreds of unranked CVEs. Vulnify groups findings into explainable **Priority Bands**:

| Band | Meaning | Typical Criteria |
| :--- | :--- | :--- |
| **P0 — Critical Immediate** | Immediate active architectural risk | Critical advisory affecting a public-facing service with direct or short transitive path. |
| **P1 — High Priority** | Urgent attention required | High advisory in public service, or Critical advisory in an internal service. |
| **P2 — Moderate Exposure** | Scheduled remediation | Moderate/Low advisories or deep transitive dependencies (> 3 hops). |
| **P3 — Low / Informational**| Backlog / Dev dependency | Test/dev utilities, non-production services, or isolated packages. |

### Triaging Findings:
1. Select any finding from the list.
2. Review the **Exposure Reasons** generated by the scoring engine (e.g., *"Public service reachable via 2 hops"*).
3. Click **Update Status** to mark the finding as:
   - `Mitigating`: Fix currently underway.
   - `Accepted`: Accepted business risk (requires written justification).
   - `Remediated`: Manually resolved or mitigated by network controls.

---

## 5. AI-Powered Security Investigation (`/intelligence`)

Vulnify includes a bounded AI investigation agent that analyzes graph paths and synthesizes remediation plans.

### 5.1 Running an Investigation
1. Navigate to **AI Investigation** (`/intelligence`).
2. Select a target finding from the dropdown (or click "Investigate with AI" directly from the Graph Explorer).
3. Enter an optional focus prompt (e.g., *"Assess the blast radius if we upgrade lodash to 4.17.21"*).
4. Click **Start Investigation**.

### 5.2 Live Streaming Trace & FastMCP Tools
The investigation streams live Server-Sent Events (SSE) into the interface:
- **Thought Stream**: Displays the agent's real-time reasoning.
- **Tool Invocations**: Shows FastMCP tool calls (such as `get_dependency_paths` or `rank_findings`) and their structured results.
- **Trace Drawer (`TraceDrawer.tsx`)**: Click **View Trace** to inspect the full timeline of tool executions, duration in milliseconds, and raw JSON payloads.

---

## 6. Fix Simulation & Upgrade Candidates (`/remediation`)

Before updating dependencies, engineers can test the safety of an upgrade.

### 6.1 Finding Upgrade Candidates (`/remediation/candidates`)
Vulnify scans the ecosystem registry to find clean, non-vulnerable versions:
- **Patch Candidate**: Minimal risk; same major/minor version (e.g., `4.17.15` -> `4.17.21`).
- **Minor Candidate**: Feature additions without breaking changes (e.g., `4.17.15` -> `4.18.0`).
- **Major Candidate**: Latest release; may introduce breaking API changes.

### 6.2 Simulating Blast Radius (`/remediation/simulate`)
1. Select the proposed upgrade version.
2. Click **Run Fix Simulation**.
3. Vulnify performs a forward traversal across your entire project graph:
   - Calculates which other microservices rely on the same package.
   - Proves whether all existing advisories for the package are eliminated.
   - Flags whether peer dependencies introduce new conflicts.

---

## 7. Human-Gated GitHub Remediation (`/remediation/github`)

When ready to open an issue for developers, Vulnify guarantees human sign-off via cryptographic plan hash verification.

```
+----------------------------------------------------------------------------------+
| Remediation Plan Preview: Upgrade lodash to 4.17.21                              |
| Target Repository: vulnify/demo-workspace                                        |
| Plan Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855    |
+----------------------------------------------------------------------------------+
| Markdown Preview:                                                                |
| ## Security Remediation                                                          |
| Upgrades lodash from 4.17.15 to 4.17.21 resolving GHSA-p6mc-m468-83gw.          |
| Impacted Services: auth-service, api-gateway                                     |
+----------------------------------------------------------------------------------+
| [ Cancel ]                                         [ Approve & Open GitHub Issue ]|
+----------------------------------------------------------------------------------+
```

1. Click **Preview GitHub Issue**.
2. Inspect the generated issue title, labels, and formatted Markdown body.
3. Review the **Plan Hash** (`SHA-256`).
4. Click **Approve & Open GitHub Issue**.
5. The backend validates the plan hash against the live graph. If verified, the issue is dispatched to GitHub via REST API v2022-11-28.
6. A success banner displays the live link to the created GitHub Issue (e.g. `https://github.com/vulnify/demo-workspace/issues/42`).
