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

## 8. Future Evaluation Harness Integration (US-802 / US-803)

This dataset serves as the immutable ground truth for:
- **US-802 (RAG Baseline & Harness):** The evaluation runner loads `benchmarks/benchmark_dataset.json`, feeds each question to both Vulnify Graph Agent and a standard Vector RAG baseline, and evaluates accuracy against `expected_answer.required_evidence` and `expected_answer.forbidden_claims`.
- **US-803 (Benchmark Results Page):** The frontend reads real evaluation run JSON outputs and renders category-by-category comparative performance metrics.
