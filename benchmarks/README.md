# Vulnify Security Investigation Benchmark (US-801)

This directory contains the hand-verified benchmark question set used to objectively evaluate the accuracy, evidence grounding, and non-exploitability compliance of the Vulnify graph-powered security investigation agent.

---

## 1. Overview & Purpose

The Vulnify Benchmark Question Set establishes reproducible ground truth across 20 carefully curated investigation scenarios. The dataset measures where graph topology provides architectural evidence that conventional RAG or text-only scanners miss or hallucinate.

### Core Tenets

1. **Exposure, Not Exploitability:** Questions evaluate architectural exposure and reachability. Benchmarks never expect or reward claims of runtime exploitability.
2. **Honest Negatives:** "No path found" queries must acknowledge depth bounds and never claim that absence of a path guarantees safety.
3. **Missing Signals:** Missing severity or network ingress signals must be treated as `"unknown"`, never defaulted to zero risk.
4. **Independent Two-Person Review:** Every benchmark answer is independently verified and approved by two distinct team members before being accepted as ground truth.
5. **No Hardcoding:** Benchmark content is stored in the version-controlled dataset, completely separate from application execution logic.

---

## 2. Directory Structure

```
benchmarks/
├── benchmark_dataset.json    # The authoritative version-controlled dataset (20 cases)
├── schema.json               # JSON Schema definition for dataset validation
└── README.md                 # Benchmark methodology, review policy, and CLI documentation
```

---

## 3. Benchmark Categories

The dataset contains 20 cases evenly distributed across the 5 official categories (4 cases each):

| Category | Identifier | Description | Key Focus |
| :--- | :--- | :--- | :--- |
| **Path Existence** | `path_exists` | Verifies directed paths from a service root to an affected package version. | Direct (depth 1), transitive (depth 2-3), and cross-service RPC call chains. |
| **No-Path Negatives** | `no_path` | Evaluates bounded traversals where no path exists. | Disjoint services, devDependencies isolation, and honest non-exploitability caveats. |
| **Architectural Exposure** | `exposure` | Analyzes network boundaries and ingress properties. | Public ingress (`internet_facing: true`), internal workers, and missing metadata. |
| **Deterministic Ranking** | `ranking` | Tests priority band assignment and deterministic tie-breaking. | Scoring policy `v1.0.0` rules, reason codes, and missing signal handling. |
| **Remediation Guidance** | `remediation` | Assesses fix recommendations, SemVer jump risk, and human gating. | Patch upgrades, no-fix guidance, major jump breaking risk, and plan hashes. |

---

## 4. Benchmark Case Schema

Each case in `benchmark_dataset.json` adheres to the following structure (validated via `benchmarks/schema.json`):

```json
{
  "id": "BM-001",
  "title": "Direct Dependency Path Verification",
  "category": "path_exists",
  "difficulty": "easy",
  "question": "Does authentication-service have a dependency path to vulnerable jsonwebtoken@8.5.1?",
  "project_id": "proj-ecommerce-core",
  "service_name": "authentication-service",
  "package_name": "jsonwebtoken",
  "package_version": "8.5.1",
  "advisory_id": "OSV-EXAMPLE-JWT-001",
  "expected_answer": {
    "conclusion": "Yes, a direct dependency path exists from authentication-service to jsonwebtoken@8.5.1 (depth 1).",
    "explanation": "Graph traversal reveals that authentication-service directly imports jsonwebtoken@8.5.1 as declared in its package manifest.",
    "required_evidence": [
      "Direct dependency path",
      "Depth 1",
      "Service: authentication-service",
      "Package: jsonwebtoken@8.5.1"
    ],
    "forbidden_claims": [
      "Claim that path does not exist",
      "Claim that dependency is transitive (depth > 1)"
    ],
    "required_caveats": [
      "Path represents architectural reachability, not proof of runtime exploitability."
    ]
  },
  "verification": {
    "status": "verified",
    "method": "graph_traversal_query",
    "query_or_tool": "get_project_finding_paths",
    "evidence_provenance": "service_manifest",
    "verified_at": "2026-10-18T10:00:00Z",
    "verification_notes": "Verified with Cypher traversal get_project_finding_paths; single DIRECT edge confirmed."
  },
  "reviews": [
    {
      "reviewer_id": "reviewer-sec-graph-lead",
      "role": "Security Graph Architect",
      "status": "approved",
      "reviewed_at": "2026-10-18T12:00:00Z",
      "dataset_version": "1.0.0",
      "notes": "Verified against FalkorDB Cypher path queries and graph schema conventions."
    },
    {
      "reviewer_id": "reviewer-appsec-lead",
      "role": "Application Security & Backend Lead",
      "status": "approved",
      "reviewed_at": "2026-10-18T12:30:00Z",
      "dataset_version": "1.0.0",
      "notes": "Verified direct dependency in package.json manifest."
    }
  ]
}
```

---

## 5. Ground Truth Verification & Evidence Provenance

Expected answers must be grounded in verified facts from Vulnify's data layer:

- **Graph Traversals:** Verified using `get_project_finding_paths.cypher` and `get_dependency_paths` tool outputs.
- **Scoring Logic:** Verified against `docs/scoring.md` (`v1.0.0`) and `vulnify.scoring.engine`.
- **Advisories:** Sourced from OSV test fixtures (`OSV-EXAMPLE-*`) with fixed version declarations.
- **Provenance Tags:**
  - `service_manifest`: Extracted from package manifests (`package.json`, `Cargo.toml`).
  - `service_lockfile`: Extracted from lockfiles (`package-lock.json`).
  - `synthetic_fixture`: Synthetic microservice topology or call edge for testing.
  - `scoring_spec`: Deterministic rules defined in `docs/scoring.md`.

---

## 6. Two-Person Review Protocol (AC2)

To prevent individual bias and ensure accuracy:

1. **Two Distinct Reviewers:** Every case must record exactly two reviews from distinct team members. One reviewer cannot fulfill both review slots.
2. **Review Outcomes:**
   - `approved`: Reviewer verified query evidence, caveats, and forbidden claims.
   - `changes_requested`: Reviewer identified inaccuracies in evidence or explanation.
   - `pending`: Review is scheduled or in progress.
   - `blocked`: Evidence is missing or ambiguous.
3. **Approval Invariant:** A case is only considered `fully_approved` when both independent reviews are `approved`. Any material edit to the question or expected answer requires re-review.

---

## 7. Running Validation and Reports

### Run Dataset Validation & Coverage Report
From the repository root:

```powershell
$env:PYTHONPATH="backend/src"
backend\.venv\Scripts\python.exe -m vulnify.benchmarks.reporter
```

### Run Automated Tests
```powershell
backend\.venv\Scripts\pytest.exe backend/tests/test_benchmarks.py
```

---

## 8. Evaluation Harness and RAG Baseline (US-802)

Vulnify implements a strictly fair, controlled experimental harness comparing the Graph-Powered Security Agent with a Retrieval-Augmented Generation (RAG) baseline.

### Experimental Fairness Protocol
1. **Shared Evidence Corpus (`benchmarks/evidence_corpus.json`):** Both systems draw from the exact same raw repository artifacts (service manifests, lockfiles, topology configurations, OSV advisories, and scoring specifications).
2. **Identical Language Model Client:** Both systems execute against the exact same language model (`gpt-4o-mini`, provider auto-selection, temperature `0.0`, identical generation constraints).
3. **Contrasting Retrieval Architectures:**
   - **Vulnify Graph Agent:** Traverses structured FalkorDB graph topology, executing bounded Cypher traversals (`*1..8`) and deterministic Priority Policy v1.0.0.
   - **RAG Baseline:** Uses BM25 lexical token-matching to retrieve top-$k$ text chunks without topology or relational links.

### Running the Comparison Harness (Single Command)
From the repository root:

```powershell
$env:PYTHONPATH="backend/src"
backend\.venv\Scripts\python.exe -m vulnify.benchmarks.runner
```

#### CLI Options
```
--dataset PATH       Path to benchmark dataset (default: benchmarks/benchmark_dataset.json)
--corpus PATH        Path to evidence corpus (default: benchmarks/evidence_corpus.json)
--output PATH        Target output JSON file (default: benchmarks/results/latest_run.json)
--category CAT       Filter by category (path_exists, no_path, exposure, ranking, remediation)
--cases ID1,ID2      Comma-separated case IDs to evaluate (e.g. BM-001,BM-002)
--llm-provider NAME  Provider override (auto, openai, gemini, deterministic_test)
--llm-model NAME     Model name override (default: gpt-4o-mini)
--temperature FLOAT  Sampling temperature (default: 0.0)
--dry-run            Simulate execution without LLM calls
--quiet              Suppress per-case execution logging
```

### JSON Results Output
The harness outputs structured JSON conforming to `benchmarks/results_schema.json` containing:
- `protocol`: Full specification of the shared model, temperature, and retrieval parameters.
- `summary`: Overall and per-category accuracy, latency, and success rates.
- `cases`: Side-by-side execution trace for each case (graph result, rag result, and evaluation score).

The latest run is atomically written to `benchmarks/results/latest_run.json`, with historical snapshots archived as `benchmarks/results/benchmark_run_{timestamp}.json`.

---

## 9. Benchmark Results Page (US-803)

The Vulnify frontend provides an interactive, honest Benchmark Results interface at `/benchmarks` for hackathon reviewers and auditors to inspect real experimental data.

### Key Capabilities & Architectural Safeguards
1. **Zero Hardcoded Metrics:** Every count, percentage, latency, category total, model name, and timestamp displayed on the page is dynamically computed from real JSON run records (`BenchmarkRunResult`) loaded via `GET /api/benchmarks/results/latest` or historical runs via `GET /api/benchmarks/results/run/{filename}`.
2. **Transparent "No Results Yet" State (AC2):**
   - If no benchmark run has been completed yet, the API returns `404 Not Found`.
   - The frontend renders a clean empty state with clear instructions on how to generate results via the single CLI command (`python -m vulnify.benchmarks.runner`) or the in-app "Run Benchmark Suite" action.
   - Placeholder or simulated numbers are **never** presented as measured facts.
3. **Explicit Small Sample Size Notice (AC1):**
   - The page prominently features a disclaimer banner emphasizing the small sample size (`N = 20` curated test cases).
   - Results are presented strictly as directional comparisons across the 5 categories rather than statistical proofs of universal superiority.
4. **Execution Status vs. Evaluated Score Honesty:**
   - Completed cases (`status === 'success'`) are labeled as **"Completed (No Faults)"** to accurately reflect error-free runtime execution, avoiding misleading conflation with ground-truth semantic accuracy.
5. **Interactive Inspection:**
   - Filter cases by category (`path_exists`, `no_path`, `exposure`, `ranking`, `remediation`).
   - Side-by-side cards comparing Graph Agent and RAG answers, latencies, and retrieved evidence citations.
   - Historical run selector dropdown to review previous evaluation runs.


