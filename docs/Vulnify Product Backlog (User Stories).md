# Vulnify: Product Backlog

*Senior business analyst view. Built as a product, not a demo. Pick stories by ID; every story has acceptance criteria you can test.*

## 1. How to use this backlog

- **ID:** US-EXX, where E is the epic number. **Release:** R1 product core, R2 hardening and depth, R3 extended. **Size** (with an AI assistant): S up to 2h, M 2-5h, L 5-10h. **Owner:** A graph and data, B backend and agent, C frontend.
- Stories are listed in build order. Take the next story whose dependencies are done. A star marks the minimum set for a credible submission.
- **Personas:** Admin (the signed-in user; one shared account for now), System (background jobs), Reviewer (a judge using the deployed product).
- **Status:** US-001 (admin login) is done.

## 2. Release plan

| Release | Goal | Stories |
| --- | --- | --- |
| R1 | Product core: load real project data, see exposure paths, prioritize, decide, act with approval, ask the agent, prove it, ship it | 001-005, 101-105, 201-204, 207, 301, 401, 501, 503-504, 601-604, 801-803, 901-902, 906-908 |
| R2 | Hardening and depth: topology, simulation, enrichment, audit, exports, scale | 106-107, 205-206, 302, 402-404, 502, 505-506, 605, 903-905 |
| R3 | Extended: monitoring, SBOM, algorithms | 108, 303, 701-702 |

**Minimum credible submission (starred):** US-002, 005, 101, 102, 103, 104, 201, 203, 204, 301, 503, 504, 601, 602, 603, 604, 801, 802, 906, 907. Your brief says the deadline is Oct 18, 11:59 PM IST; confirm that on the official page. If it holds, do the starred stories first and treat everything else as optional.

## 3. Build order (blocks)

| Block | Theme | Stories | Result |
| --- | --- | --- | --- |
| 1 | Foundations | 002, 004, 005, 003 | Anyone can run it; consistent errors and API contract |
| 2 | Data in | 101, 102, 103, 104, 105 | A real project loaded into FalkorDB with advisories matched |
| 3 | See it | 201, 202, 203, 204, 207 | Findings list and an evidence-backed path |
| 4 | Prioritize | 301 | Ranked findings with reasons |
| 5 | Decide and act | 401, 501, 503, 504 | Record a decision, approve, create a GitHub issue |
| 6 | Agent | 601, 602, 603, 604 | Ask questions, stream tool calls, stored traces |
| 7 | Prove and ship | 801, 802, 803, 901, 902, 906, 907, 908 | Benchmark, accessibility, deployment, documentation |

## 4. Definition of done and quality bars

**A story is done when:**

- Acceptance criteria pass and a second teammate has verified them.
- Tests exist for new logic (queries, matching, ranking, approval gating) and pass in CI.
- Typecheck, lint and tests pass; no secrets or .env files are committed.
- Every new screen has loading, empty, error and populated states.
- Any contract change is reflected in docs/api.md, the backend models and the frontend types.
- Data shown has provenance (source, retrieved at); anything synthetic is labelled.
- The AI-assistance note is updated and the author can explain the code.

**Non-functional requirements (apply to every story):**

- **Security:** httpOnly session cookie, CSRF header on writes, no default credentials, least-privilege GitHub token, advisory text treated as untrusted and never rendered as HTML.
- **Honesty:** a path means architectural exposure, not exploitability; 'no path found' never means safe.
- **Performance:** findings list under 2 seconds for 500 findings; path query under 1 second on the demo graph.
- **Reliability:** ingestion is idempotent; partial failures are reported, never hidden.
- **Accessibility:** WCAG AA contrast, full keyboard use, labelled controls.
- **Privacy:** public or synthetic data only; no maintainer names or usernames stored.
- **Auditability:** admin actions are logged with who, when and what.

## 5. Epic E0: Foundations

### US-001 Admin sign in and out (R1, done)

As an **admin**, I want to sign in with my credentials, so that only authorized people use the features.

- Done: login page, httpOnly session cookie, protected routes, logout, generic error on bad credentials, rate limiting.
- Further hardening is tracked in US-901.

### US-002 One-command local environment (R1, M, A+B) ★

As a **team member**, I want to start everything with one command, so that anyone can run the product from a clean clone.

- `docker compose up` starts FalkorDB, the backend and the frontend.
- `GET /api/health` reports API status and FalkorDB connectivity separately.
- A teammate who has never seen the repo runs it by following the README only.
- Configuration comes from .env (a .env.example with placeholders is committed; real secrets are not).

### US-003 Engineering standards and CI (R1, S, B)

As a **team member**, I want automated checks on every push, so that broken code is caught early.

- CI runs frontend typecheck, backend lint and tests.
- A failing check blocks merging to main.
- The pull request template includes a checkbox for AI-assistance disclosure and a secrets check.

### US-004 Consistent errors and logging (R1, S, B)

As an **admin**, I want clear error messages, so that I know what went wrong and what to do.

- Every API error returns `{code, message, request_id}`.
- Backend logs are structured and include the request ID; passwords, tokens and advisory bodies are never logged.
- The frontend shows a friendly message plus the request ID for unexpected errors.

### US-005 API contract and typed client (R1, S, B+C) ★

As a **developer**, I want one documented contract, so that frontend and backend can be built in parallel.

- docs/api.md lists every endpoint, request, response and error shape, including the SSE event format.
- Backend Pydantic models and frontend TypeScript types match; a contract test covers the key endpoints.
- The frontend calls the API only through one client module and typed hooks.

## 6. Epic E1: Projects and data ingestion

### US-101 Create and select a project (R1, S, B+C) ★

As an **admin**, I want to create a project, so that I can analyze its dependencies.

- A project has a name (unique), ecosystem (one supported ecosystem at first) and optional description.
- Projects are stored in FalkorDB and listed; a selector in the top bar switches the active project.
- The selected project persists across refresh; an empty-projects state guides the user to create one.
- Invalid input shows field-level errors.

### US-102 Import dependencies from a lockfile (R1, L, A+C) ★

As an **admin**, I want to upload a project's lockfile for a named service, so that its real dependency graph is stored.

- Parses packages and their dependency links into PackageVersion nodes and DEPENDS\_ON edges attached to the service.
- Shows an import summary: packages, edges, skipped entries, errors.
- Rejects unsupported or oversized files with a clear message; nothing in the file is ever executed.
- Records provenance (file name, hash, imported at).
- Importing the same file twice creates no duplicate nodes or edges.
- A lockfile with 5,000 packages imports in under 30 seconds.

### US-103 Import advisories from OSV (R1, L, A) ★

As an **admin**, I want known vulnerabilities fetched for my packages, so that findings are based on real advisories.

- Looks up advisories for each imported package version and stores Vulnerability nodes with id, summary, severity, affected ranges, fixed versions, source URL and retrieved-at.
- Responses are cached; rate limits and timeouts are handled with backoff.
- A partial failure keeps the progress already made and lists the packages that failed.
- Source terms and license are documented in docs/data-sources.md.

### US-104 Ecosystem-aware version matching (R1, M, A) ★

As an **admin**, I want affected versions matched correctly, so that I do not get false alarms or miss real ones.

- Uses the ecosystem's real version rules, never plain string comparison.
- A test table of at least 20 cases covers boundaries, pre-releases and fixed versions, and passes.
- A match creates an AFFECTS edge and stores why it matched (version, range).
- One known-affected and one known-unaffected version are verified against a real advisory.

### US-105 Ingestion jobs and history (R1, M, A+B)

As an **admin**, I want to see import progress and past runs, so that I trust the data.

- Imports run as background jobs with status (queued, running, succeeded, partial, failed), progress and timestamps.
- A history list shows who started each run and its counts.
- Re-running is idempotent: counts stay stable and no duplicates appear.
- Failures show an actionable message and can be retried.

### US-106 Service topology import (R2, L, A+C)

As an **admin**, I want to describe services, which are internet-facing and which call which, so that exposure reflects the real system.

- Accepts a topology file (services, internet\_facing flag, calls) and validates it with line-level errors.
- Every fact stores its source; synthetic entries are flagged.
- Cyclic calls are handled; traversals are depth-bounded.

### US-107 Refresh advisories on demand (R2, S, A+C)

As an **admin**, I want to re-check for new advisories, so that findings stay current.

- A Refresh action re-queries advisories for known package versions and reports how many new matches appeared.
- The last refresh time is visible; data older than 7 days shows a stale-data warning.

### US-108 SBOM import (R3, M, A)

As an **admin**, I want to import a software bill of materials, so that I can analyze projects without a lockfile.

- Supports one common SBOM format; unsupported formats are rejected with guidance.
- Result is the same graph shape as a lockfile import, with provenance.

## 7. Epic E2: Findings and investigation

### US-201 Findings list (R1, M, B+C) ★

As an **admin**, I want to see all findings for the active project, so that I know where to look.

- Columns: priority, advisory, package and version, service, path depth, status.
- Filter by priority, service and status; search by advisory or package; paginated (25 per page); filters appear in the URL.
- Loading, empty, error and populated states exist; 500 findings load in under 2 seconds.
- Protected by login (401 returns the user to sign in).

### US-202 Summary cards (R1, S, B+C)

As an **admin**, I want a quick summary, so that I see the overall picture.

- Cards show advisory matches, findings with a path, findings with no path, and findings needing a decision.
- All numbers are computed on the server from stored data and add up to the list totals.

### US-203 Finding detail and evidence (R1, M, B+C) ★

As an **admin**, I want the evidence behind a finding, so that I can trust and act on it.

- Shows advisory ID and summary, severity, affected range, fixed version, matched version and why it matched, source link and retrieved-at.
- Advisory text is rendered as plain text only.
- Unknown finding IDs show a not-found page.

### US-204 Dependency path view (R1, M, A+C) ★

As an **admin**, I want to see how my service reaches the affected package, so that I understand the exposure.

- Shows up to the shortest few paths from the service to the affected version, depth-bounded.
- Handles direct and transitive dependencies; each node shows its provenance.
- The path is drawn as a readable chain with a text alternative for screen readers.
- The path comes from a FalkorDB query that is documented in docs/cypher-catalog.md.

### US-205 Architectural exposure path (R2, L, A+C)

As an **admin**, I want to know whether an internet-facing service can reach the affected service, so that I can prioritize.

- Shows internet, entry service, service calls and package chain in one path.
- The screen always says 'architectural exposure, not proof of exploitability'.
- Synthetic edges are visibly flagged; unsupported ecosystems are listed as not analyzed.

### US-206 Blast radius (R2, M, A+C)

As an **admin**, I want to see everything that uses a package version, so that I know the impact of a fix.

- Selecting a package version lists the services and projects that depend on it, directly or transitively, with a count.

### US-207 Honest empty and warning states (R1, S, B+C)

As an **admin**, I want clear 'no path' and data-quality messages, so that I never mistake missing data for safety.

- 'No path found' states that this does not guarantee safety.
- Warnings appear for missing topology, stale advisory data and partial imports.

## 8. Epic E3: Prioritization

### US-301 Priority bands with reasons (R1, M, B) ★

As an **admin**, I want findings ranked with understandable reasons, so that I fix the right things first.

- Rules are documented in docs/scoring.md (bands Highest, High, Medium, Low plus tie-breakers) and implemented deterministically.
- Every finding shows its band and the reasons; missing signals show as unknown, not zero.
- Unit tests cover each band; the same input always gives the same output; the scoring version is stored with each result.

### US-302 Known-exploited and exploit-likelihood signals (R2, M, A)

As an **admin**, I want public exploitation signals used in ranking, so that urgent issues rise.

- Imports a public known-exploited list and exploit-likelihood scores with source and date; refreshable.
- Findings show these signals or 'unknown'.

### US-303 Hub package ranking (R3, M, A)

As an **admin**, I want to see the most depended-on packages, so that I know where risk concentrates.

- Lists top packages by dependents using a graph measure (verify FalkorDB support); used as a tie-breaker and documented.

## 9. Epic E4: Triage workflow

### US-401 Record a decision on a finding (R1, M, B+C)

As an **admin**, I want to mark a finding as affected, not affected, fixed or under investigation, so that the team's judgment is captured.

- Statuses: open, under investigation, affected, not affected, fixed. 'Not affected' requires a written justification.
- Each decision stores who, when and why, and the history is visible on the finding.
- The findings list can be filtered by status; the summary 'needs decision' count updates.

### US-402 Decisions are respected (R2, S, B)

As an **admin**, I want settled findings not to be re-raised without cause, so that I am not asked the same thing twice.

- A finding marked not affected stays quiet unless the advisory, the version or the path changes; then it is flagged 'needs review' with the reason.
- The agent and the ranking both read prior decisions.

### US-403 Audit trail (R2, M, B+C)

As an **admin**, I want a record of important actions, so that I can review what happened and when.

- Logs sign-ins, imports, decisions, approvals and issue creation with who, when and what; entries cannot be edited or deleted.
- A page lists entries with filters and CSV export.

### US-404 Export a report (R2, M, B+C)

As an **admin**, I want to export findings, so that I can share them outside the tool.

- Exports CSV and a printable report with priority, reasons, paths, provenance and timestamps.
- Exported text contains no secrets and marks synthetic data.

## 10. Epic E5: Remediation and action

### US-501 Candidate upgrades (R1, M, A+B)

As an **admin**, I want suggested upgrade targets, so that I know how to fix a finding.

- Candidates come from the advisory's fixed versions and are labelled recommended, major version or patch only.
- Compatibility caveats are shown; the tool never claims an upgrade is safe to ship.
- When no fixed version exists, a clear 'no fix available' state appears.

### US-502 Fix simulation (R2, L, A+B)

As an **admin**, I want to see what an upgrade would change, so that I choose with confidence.

- Runs on a scenario copy or overlay of the graph and shows findings cleared, unchanged and newly introduced.
- Labels the method as simulated from metadata or verified in a sandbox.
- The scenario never changes the real graph.

### US-503 Issue preview (R1, M, B+C) ★

As an **admin**, I want to review exactly what will be filed, so that nothing surprising is created.

- The preview is built from structured fields (advisory, versions, paths, caveats) and never copies raw advisory text.
- It shows a plan hash; editing the title resets the review checkbox and creates a new hash.
- Nothing is created while only previewing.

### US-504 Approve and create a GitHub issue (R1, L, B+C) ★

As an **admin**, I want to approve and create the issue in one step, so that remediation work is tracked.

- The button is disabled until the preview is reviewed; the backend verifies the plan hash and a CSRF header before acting.
- Targets only the configured team-owned repository using a least-privilege token from the environment.
- Re-submitting the same plan does not create a duplicate; it returns the existing issue link.
- Failures show a clear message with retry; success shows the issue link.
- The action is written to the audit trail.

### US-505 Action history (R2, S, B+C)

As an **admin**, I want a list of issues the tool created, so that I can follow up.

- Shows issue link, plan hash, who approved, when and the findings covered.

### US-506 Configure the GitHub target (R2, S, B+C)

As an **admin**, I want to set the target repository, so that issues go to the right place.

- The owner and repo name are validated against the token's access; the token is never displayed.
- Misconfiguration blocks issue creation with a clear message.

## 11. Epic E6: Agent

### US-601 Tool registry and MCP server (R1, L, B) ★

As the **system**, I want the agent to use fixed, tested graph tools, so that its answers are grounded and safe.

- Each tool lives in its own file with typed inputs and outputs, wraps a parameterized query and returns data plus a trace fragment.
- The same registry is exposed over MCP; tools are read-only except the gated decision and issue tools.
- The agent never writes Cypher or shell commands; each tool has a unit test; tools are listed in docs/agent-tools.md.

### US-602 Ask the agent (R1, L, B+C) ★

As an **admin**, I want to ask questions in plain language, so that I can investigate quickly.

- Chat streams tool steps and the final answer over SSE; a stop button cancels a run.
- Runs have a step limit and a timeout, and show clear errors.
- Answers reference finding IDs and paths; only a signed-in admin can use the endpoint.

### US-603 Stored traces (R1, M, B+C) ★

As an **admin**, I want to see how an answer was produced, so that I can verify it.

- Each run is stored with tool calls, inputs, result summaries and query identifiers.
- A trace drawer opens from chat and from a finding; past runs can be reopened.

### US-604 Resistance to hostile advisory text (R1, M, B) ★

As the **system**, I want untrusted text never to steer the agent, so that attackers cannot misuse it.

- A fixture advisory containing instruction-like text does not change tool calls, answers or the issue body (automated test).
- Untrusted text is passed as delimited data and never rendered as HTML.
- The approach is documented in docs/agent-safety.md.

### US-605 Grounded answers (R2, S, B)

As an **admin**, I want the agent to admit what it does not know, so that I am not misled.

- When the graph lacks evidence, the answer says so instead of guessing.
- The agent never describes a finding as exploitable.

## 12. Epic E7: Monitoring

### US-701 Scheduled advisory re-check (R3, M, A+B)

As the **system**, I want to check for new advisories regularly, so that findings stay current without manual work.

- A schedule re-checks known packages and records new matches with a timestamp; failures are logged and retried.

### US-702 New high-priority alerts (R3, M, B+C)

As an **admin**, I want to be told about new urgent findings, so that I can respond.

- A notification appears in the app when a new Highest or High finding is created; it links to the finding and can be dismissed.

## 13. Epic E8: Quality evidence

### US-801 Benchmark question set (R1, M, A+B) ★

As the **team**, I want hand-verified test questions, so that we can measure the agent honestly.

- About 20 questions across path existence, no-path, exposure, ranking and remediation, each with a verified answer, stored in the repo.
- Two team members review each answer.

### US-802 RAG baseline and harness (R1, L, B) ★

As the **team**, I want a fair comparison, so that we know where the graph helps.

- The baseline uses the same evidence and the same language model.
- One command runs both systems and writes results as JSON.
- Results are reproducible from a clean setup; errors are reported, not hidden.

### US-803 Benchmark results page (R1, S, C)

As a **reviewer**, I want to see measured results, so that I can judge the approach.

- Reads real results and shows correct counts per category for both systems; clearly states the small sample size.
- Shows a 'no results yet' state until a run exists; never displays placeholder numbers as measured.

## 14. Epic E9: Hardening and release

### US-901 Session and access hardening (R1, S, B)

As an **admin**, I want secure sessions, so that my account is protected.

- Expired sessions return the user to sign in with a clear message; any 401 on an API call does the same.
- Secure cookies are enforced in production; CSRF and rate limiting have automated tests; no default credentials exist.

### US-902 Accessibility pass (R1, M, C)

As a **user with assistive technology**, I want every screen to be usable, so that I am not excluded.

- Full keyboard operation, visible focus and labelled controls on all main screens.
- Text meets AA contrast; an automated accessibility scan shows no serious issues.

### US-903 Performance and scale check (R2, M, A)

As the **team**, I want known performance limits, so that the product holds up with real data.

- A seeded graph of at least 5,000 package versions is loaded; path queries stay under 1 second (95th percentile) and the findings list under 2 seconds.
- Results and indexes are documented.

### US-904 Observability (R2, S, B)

As the **team**, I want to see what the system is doing, so that we can diagnose problems.

- Request logs, ingestion metrics and a detailed health endpoint are available; every error carries a request ID.

### US-905 Backup, restore and reset (R2, S, A)

As the **team**, I want to back up and reset data, so that we can recover and demo reliably.

- Documented FalkorDB dump and restore; a command resets and reloads the demo dataset.

### US-906 Deployment (R1, L, A+B+C) ★

As a **reviewer**, I want to use a live deployment, so that I can evaluate the product without setup.

- Frontend, backend and FalkorDB run in a hosted environment over HTTPS with secure cookies.
- Deep links and refresh work (single-page-app rewrites); environment variables are documented.
- A smoke-test checklist passes after each deploy; a rollback note exists.
- A throwaway demo login is shared with reviewers in the submission notes, not committed.

### US-907 Documentation and submission pack (R1, M, all) ★

As a **reviewer**, I want complete documentation, so that I understand and can reproduce the work.

- README with setup, graph model, essential Cypher and algorithms, scoring rules, data sources with licenses, limitations, track declaration and the AI-assistance disclosure.
- Public repository, demo video and a backup recording are ready.
- Every team member can explain the code they own.

### US-908 Real dataset loader (R1, M, A)

As a **reviewer**, I want the product to open with real, loaded data, so that I can explore without importing anything.

- A command or first-run action loads the chosen real project and its advisories; running it twice creates no duplicates.
- Synthetic items, if any, are labelled and listed in docs/data-sources.md.

## 15. Traceability to hackathon requirements

| Requirement | Stories |
| --- | --- |
| FalkorDB is primary; the graph does real work | 102-104, 204, 205, 206, 301 |
| Multi-hop reasoning | 204, 205, 206 |
| Graph queries and algorithms as agent tools via MCP | 601, 602, 303 |
| An action based on the results | 503, 504 |
| Explainable results (path, evidence, trace) | 203, 204, 603 |
| Public or synthetic data only | 102, 103, 908 and the privacy requirement |
| Public repo, README, graph model, Cypher | 907 |
| Live deployment or full local setup | 002, 906 |
| Demo video | 907 |
| AI-assistance disclosure | 907 and the definition of done |

## 16. Decisions needed before building

1. **Ecosystem:** npm or PyPI for the first release.
2. **Demo project:** a real public project with a lockfile, and one real advisory that affects it.
3. **GitHub target:** a team-owned repository for created issues, and a fine-grained token.
4. **Language model provider:** confirm tool calling works end to end on day one.
5. **Hosting:** where the frontend, backend and FalkorDB will run.
6. **Deadline:** confirm the official date and time.
7. **Accounts:** one shared admin for now; multiple users would be a new epic.
