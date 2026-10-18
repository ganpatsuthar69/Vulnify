# Vulnify — Testing & Quality Assurance Strategy

> **Testing Architecture, Test Suite Catalog, Accessibility Audits, and Benchmark Harness**  
> *A comprehensive guide to verifying correctness, performance, and security across Vulnify.*

---

## 1. Testing Philosophy & Quality Gates

Vulnify enforces a multi-tiered quality assurance strategy. Because security teams rely on Vulnify for critical architectural decisions, testing guarantees:
1. **Mathematical Accuracy**: Dependency path discovery and version range evaluations are tested against complex multi-hop graphs.
2. **Deterministic Priority Scoring**: Risk priority bands (P0-P3) produce consistent, explainable results without model drift.
3. **Sub-50ms Graph Performance**: Bounded traversals are tested under load to ensure graph operations do not introduce latency spikes.
4. **Complete Accessibility (a11y)**: Frontend interfaces are tested against WCAG 2.1 AA standards via automated `axe-core` audits.
5. **Human Gating Enforcement**: Integration tests verify that mutating actions (e.g. GitHub issue creation) reject invalid plan hashes.

---

## 2. Backend Test Suites (`backend/tests/`)

Backend tests are powered by **Pytest** and **pytest-asyncio**, utilizing `httpx.AsyncClient` for in-memory ASGI testing.

### 2.1 Test Directory Structure

```
backend/tests/
├── agent/                                    # FastMCP and AI orchestrator test suites
│   ├── test_agent_orchestrator.py            # Bounded loop iterations and timeouts
│   ├── test_agent_tools.py                   # FastMCP tool execution and error handling
│   └── test_trust_boundary.py                # Prompt injection and context sanitization
├── fixtures/                                 # Test lockfiles, sample graphs, and manifests
├── conftest.py                               # Shared async fixtures, test DB client, test users
├── test_auth.py                              # Registration, login, session cookies, Argon2
├── test_benchmarks.py                        # Benchmark suite execution and scoring
├── test_benchmark_harness.py                 # Ground-truth evaluation harness
├── test_cargo_parser.py                      # Cargo.lock AST parsing and dependency resolution
├── test_golang_parser.py                     # go.mod and go.sum parser validation
├── test_python_parser.py                     # requirements.txt, Pipfile.lock, and poetry.lock
├── test_lockfile_parser.py                   # npm package-lock.json v1/v2/v3 parsing
├── test_change_detection.py                  # Ingestion diffing and incremental updates
├── test_database_health.py                   # FalkorDB connectivity and ping checks
├── test_data_quality_warnings_api.py         # Missing manifests and unmapped package warnings
├── test_dependency_import_api.py             # Multipart lockfile upload endpoint
├── test_dependency_import_graph.py           # Ingestion Cypher queries and edge persistence
├── test_dependency_import_multi_ecosystem.py # Mixed-ecosystem dependency graph linking
├── test_ecosystem_ingestion_regression.py    # Regression coverage across package ecosystems
├── test_ecosystem_registry.py                # Supported ecosystem definitions
├── test_errors_and_logging.py                # Standardized error responses & X-Request-ID
├── test_exposure_paths_api.py                # Public entrypoint reachability traversals
├── test_findings_api.py                      # Finding list pagination and priority filtering
├── test_findings_performance.py              # Sub-50ms latency assertions under graph load
├── test_findings_summary_api.py              # Aggregated metrics and priority band distribution
├── test_finding_detail_api.py                # Advisory details, CVSS vectors, and references
├── test_finding_paths_api.py                 # Shortest-first path matching algorithms
├── test_fix_simulation_api.py                # Forward-traversal upgrade blast radius
├── test_github_admin_config.py               # Admin token encryption and repository settings
├── test_github_issues_api.py                 # SHA-256 plan hash gating and issue creation
├── test_graph_explorer.py                    # Graph canvas serialization and node layouts
├── test_graph_path_benchmark.py              # Path query benchmarks across graph sizes
├── test_import_performance.py                # Batch UNWIND throughput and memory limits
├── test_ingestion_jobs.py                    # Asynchronous ingestion job tracking
├── test_osv_api.py                           # OSV client, rate limiting, and backoff retries
├── test_osv_ingestion_regression.py          # OSV payload parsing and version match edge cases
├── test_projects.py                          # Project CRUD operations and validation
├── test_project_data_isolation.py            # Multi-tenant project data isolation assertions
├── test_scoring_engine.py                    # P0-P3 priority scoring calculation
├── test_upgrade_candidates_api.py            # Semver patch, minor, and major candidate discovery
└── test_version_matching.py                  # Strict semver and PEP 440 range evaluation
```

---

### 2.2 Running Backend Tests

Navigate to `backend/` and run Pytest:

```bash
# Run all tests
pytest -v

# Run a specific test suite
pytest tests/test_findings_api.py -v

# Run performance and latency assertions only
pytest tests/test_findings_performance.py -v

# Run with test coverage report
pytest --cov=vulnify --cov-report=term-missing
```

---

## 3. Frontend Test Suites (`frontend/src/tests/`)

Frontend testing is driven by **Vitest**, **React Testing Library**, and **axe-core**.

### 3.1 Suite Inventory
- **Accessibility Audits (`a11y.test.tsx`, `a11y-layout.test.tsx`, `a11y-views.test.tsx`)**:
  - Validates that color contrast ratios, ARIA roles, form labels, and focus indicators comply with WCAG 2.1 AA standards.
  - Ensures screen readers can navigate graph explorer views and remediation dialogs.
- **Project Isolation Tests (`project-isolation.test.tsx`)**:
  - Verifies that switching active projects in the UI immediately resets graph canvas nodes and findings lists, preventing cross-project UI bleed.
- **Graph Explorer Tests (`graph-explorer.test.ts`)**:
  - Validates node-type badge rendering, relationship styling, and hierarchical layout calculations.
- **Benchmark API Client Tests (`benchmarkApi.test.ts`)**:
  - Tests API communication with the backend evaluation harness.

---

### 3.2 Running Frontend Tests & Linting

Navigate to `frontend/`:

```bash
# Run Vitest unit & accessibility tests
npm test

# Run Vitest in watch mode
npm run test:watch

# Execute complete TypeScript build check
npm run build
```

---

## 4. Benchmark & Evaluation Harness (`benchmarks/`)

Vulnify includes a dedicated benchmark suite located in `benchmarks/` designed to evaluate graph traversal precision and agent reasoning against verified ground truth.

### 4.1 Benchmark Components
- **`benchmark_dataset.json`**: Ground-truth dataset containing 50+ curated dependency topologies across npm, PyPI, Cargo, and Go, pairing real and synthetic packages with known CVEs.
- **`evidence_corpus.json`**: Gold-standard evidence snippets, path assertions, and priority rankings used to benchmark the AI agent's reasoning accuracy.
- **`schema.json` & `results_schema.json`**: JSON Schema definitions validating benchmark inputs and outputs.
- **Harness Endpoints**:
  - `GET /api/benchmarks/dataset`: Retrieves benchmark test cases.
  - `POST /api/benchmarks/run`: Executes benchmark test runs.
  - `GET /api/benchmarks/runs/{id}`: Returns execution latency, path recall, and accuracy metrics.

---

## 5. Mocking Policy & Sample Data Integrity

Vulnify adheres to strict standards regarding mock data:
- **No Mock Data in Production**: Production deployments run exclusively against live FalkorDB instances and real OSV.dev advisories.
- **Explicit Test Identifiers**: All synthetic test records use explicitly reserved naming conventions (`OSV-EXAMPLE-*`, `test-project-xyz`).
- **No Fabricated Exploitability Claims**: Tests assert whether paths connect nodes, never claiming that synthetic findings constitute real-world exploitable exploits.
