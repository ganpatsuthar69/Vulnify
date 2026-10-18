# Vulnify GitHub Remediation Integration Guide (US-503 & US-504)

## 1. Overview & Architecture

Vulnify enables authorized security engineers to preview structured vulnerability remediation plans and, following explicit human approval, file remediation issues directly in a configured GitHub repository.

### Core Security Principles
- **Least-Privilege Token**: Issues are created using a server-side fine-grained GitHub Personal Access Token (PAT) limited strictly to the team-owned repository with `Issues: Read and write` access.
- **Credential Isolation**: GitHub tokens and credentials remain exclusively on the backend. They are never exposed to the browser, serialized into frontend API responses, or recorded in audit logs.
- **Cryptographic Plan-Hash Binding (US-503)**: Every remediation issue preview computes a deterministic SHA-256 plan hash (`plan_sha256_<16-chars>`) covering project, finding, repository, title, and body. Any edit immediately recomputes the plan hash and invalidates prior review or approval.
- **Mandatory Human Approval Gating (US-504)**: The backend rejects any creation request lacking explicit human confirmation (`confirmed: true`), valid CSRF protection header (`X-Requested-With: vulnify`), or having a mismatched/stale plan hash.
- **Restricted Destination Repository**: Issues can only be created in the configured team-owned repository (`GITHUB_DEFAULT_OWNER/GITHUB_DEFAULT_REPO`). Arbitrary destination repositories supplied by clients are rejected with `400 Bad Request`.
- **Honest Evidence & Markdown Safety**: Advisory summaries and descriptions are treated as untrusted input. Raw unquoted advisory text is never copied into issue descriptions; HTML tags are escaped (`<` -> `&lt;`, `>` -> `&gt;`). Exposure is explicitly noted as structural reachability rather than proof of exploitability.

---

## 2. Configuration & Environment Variables

Configure the following variables in `backend/.env` (documented in `backend/.env.example`):

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `GITHUB_API_BASE_URL` | string | `https://api.github.com` | Upstream GitHub REST API endpoint. |
| `GITHUB_TOKEN` | string | `None` | Fine-grained GitHub PAT with `Issues: Read and write` permission. |
| `GITHUB_DEFAULT_OWNER` | string | `vulnify` | Owner/organization of the authorized repository. |
| `GITHUB_DEFAULT_REPO` | string | `demo-workspace` | Name of the authorized repository. |
| `GITHUB_API_TIMEOUT_SECONDS` | int | `15` | Timeout for GitHub REST API calls. |
| `GITHUB_API_VERSION` | string | `2022-11-28` | GitHub REST API version header. |

> [!IMPORTANT]
> Never commit `.env` or real GitHub tokens to version control. If `GITHUB_TOKEN` is unset or blank, issue previewing remains operational, but issue creation will fail closed with `400 Bad Request` until credentials are provided.

---

## 3. GitHub Token Setup Guide

To configure the least-privilege token for Vulnify:

1. Sign in to GitHub and navigate to **Settings** &rarr; **Developer Settings** &rarr; **Personal Access Tokens** &rarr; **Fine-grained tokens**.
2. Select **Generate new token**.
3. **Repository access**: Select **Only select repositories** and choose your team-owned repository (e.g., `vulnify/demo-workspace`).
4. **Permissions**: Under **Repository permissions**, configure:
   - **Issues**: `Read and write`
   - All other permissions: `No access`
5. Set token expiration according to organizational policy (e.g., 30 or 90 days).
6. Copy the token string and add it to `backend/.env`:
   ```bash
   GITHUB_TOKEN=github_pat_11A...
   GITHUB_DEFAULT_OWNER=your-org
   GITHUB_DEFAULT_REPO=your-repo
   ```

---

## 4. End-to-End Workflow

```
[Finding Detail / Simulation Page]
           │
           ▼
1. GET /api/projects/{proj_id}/github/status
   ├── Verifies server token configuration
   └── Obtains authorized target repo
           │
           ▼
2. POST /api/projects/{proj_id}/findings/{id}/github-issues/preview
   ├── Generates structured Markdown body with graph evidence
   └── Computes authoritative SHA-256 plan hash
           │
           ▼
3. Operator Reviews Preview in UI
   ├── Editing title/notes recomputes hash and resets checkbox
   └── Explicitly checks "I have reviewed and approve..."
           │
           ▼
4. POST /api/projects/{proj_id}/findings/{id}/github-issues
   ├── Enforces CSRF header: X-Requested-With: vulnify
   ├── Validates confirmed == true
   ├── Verifies target_repo == configured team repo
   ├── Validates plan_hash integrity against server preview
   ├── Concurrency Lock (asyncio.Lock per plan hash)
   ├── Idempotency Check: Returns existing issue if duplicate
   ├── Reconciles uncertain outcomes if previous attempt timed out
   ├── Calls GitHub API: POST /repos/{owner}/{repo}/issues
   ├── Records structured audit event (success, rejected, or failed)
   └── Returns GitHub issue number, state, and direct clickable URL
           │
           ▼
5. UI displays confirmed issue link or duplicate notification
```

---

## 5. Idempotency & Uncertain Outcome Reconciliation

### Idempotent Duplicate Prevention (US-504 AC-3)
Submitting the same approved plan hash multiple times returns the previously created issue record with:
- `is_duplicate: true`
- Message: `"An issue for this exact remediation plan was already created (Issue #N). Duplicate creation prevented."`
- The upstream GitHub REST API is **not** called a second time.

### Concurrency Protection
To protect against race conditions from concurrent browser requests, `GitHubService` employs an `asyncio.Lock` per plan hash. The second request waits until the first completes and returns the cached issue without making duplicate external calls.

### Network Timeout Reconciliation (US-504 Section 4.6)
If a network timeout occurs while waiting for GitHub's response:
1. The request fails with `504 Gateway Timeout` and marks the attempt state as `timeout_uncertain`.
2. An audit event is logged with `result: "failed"`, `failure_category: "timeout_uncertain"`.
3. When the user retries with the same plan hash, Vulnify queries `GET /repos/{owner}/{repo}/issues` to inspect recent issues.
4. If the issue was already created upstream by GitHub prior to the timeout, Vulnify reconciles the issue, registers it in the local cache, and returns it with `is_duplicate: true` without issuing another `POST` request.

---

## 6. Audit Trail Logging (US-504 AC-5)

Every issue preview and creation attempt records a structured audit event in the server logs:

```json
{
  "timestamp": 1729173000,
  "actor": "admin@vulnify.local",
  "action": "create_github_issue",
  "project_id": "proj-1",
  "finding_id": "find-1",
  "plan_hash": "plan_sha256_e3b0c44298fc1c14",
  "target_repo": "vulnify/demo-workspace",
  "result": "success",
  "failure_category": null,
  "request_id": "req-80aa5cb1fca44593",
  "issue_number": 42,
  "issue_url": "https://github.com/vulnify/demo-workspace/issues/42"
}
```

Audit entries explicitly record rejections (`result: "rejected"`, e.g., missing approval, hash mismatch, unauthorized repo) and failures (`result: "failed"`, e.g., token missing, 403 forbidden, 429 rate limit, 504 timeout). **Secrets, tokens, authorization headers, and session cookies are strictly excluded from all audit records.**
