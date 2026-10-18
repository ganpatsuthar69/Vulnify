# Vulnify — API Reference

> **Complete REST and Streaming API Reference**  
> *Authoritative specification for all endpoints, headers, request/response models, and Server-Sent Events.*

---

## 1. Global API Conventions

### Base URL & Versioning
- **Local Development Base URL**: `http://127.0.0.1:8000`
- **Frontend Proxy Route**: `/api/...` (proxied by Vite to the backend)
- **Current API Version**: `0.2.0` (FastAPI title: *Vulnify API*)
- **Interactive Documentation**:
  - Swagger UI: `GET /docs`
  - ReDoc UI: `GET /redoc`
  - OpenAPI JSON: `GET /openapi.json`

---

### Global Request Headers

| Header Name | Required | Applicable Methods | Description |
| :--- | :--- | :--- | :--- |
| `Content-Type` | Yes | `POST`, `PUT`, `PATCH` | Must be `application/json` (or `multipart/form-data` for file upload). |
| `X-Requested-With`| **Yes** | `POST`, `PUT`, `PATCH`, `DELETE` | Must be exactly `vulnify`. Enforced by `CSRFMiddleware`. |
| `Origin` | Conditionally | `POST`, `PUT`, `PATCH`, `DELETE` | Validated against `ALLOWED_ORIGINS` to prevent CSRF attacks. |
| `X-Request-ID` | No | All Methods | Optional client trace identifier. Generated automatically if omitted. |
| `Cookie` | Yes (Auth) | Protected Endpoints | Contains `vulnify_session=<token>` session cookie. |

---

### Global Response Headers

| Header Name | Description |
| :--- | :--- |
| `X-Request-ID` | Unique UUIDv4 assigned to each request for end-to-end log tracing. |
| `Set-Cookie` | Present on `/api/auth/login` and `/api/auth/register`. Configured with `HttpOnly; SameSite=Lax; Path=/`. |

---

### Standardized Error Format
All 4xx and 5xx error responses conform strictly to this unified schema:

```json
{
  "code": "ERROR_CODE_STRING",
  "message": "Human-readable description.",
  "request_id": "req-9b8a7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"
}
```

#### Canonical Error Codes

| Error Code | HTTP Status | Description |
| :--- | :--- | :--- |
| `CSRF_ERROR` | `403 Forbidden` | Missing or invalid `X-Requested-With` header or untrusted `Origin`. |
| `AUTHENTICATION_REQUIRED` | `401 Unauthorized` | Missing, expired, or invalid session cookie. |
| `INVALID_CREDENTIALS` | `401 Unauthorized` | Incorrect email or password during login. |
| `FORBIDDEN` | `403 Forbidden` | Authenticated user lacks required permissions (e.g., non-admin calling admin routes). |
| `NOT_FOUND` | `404 Not Found` | The requested project, finding, job, or resource does not exist. |
| `VALIDATION_ERROR` | `422 Unprocessable`| Pydantic payload validation failure. |
| `CONFLICT` | `409 Conflict` | Unique constraint violation (e.g., duplicate user or duplicate import hash). |
| `PLAN_HASH_MISMATCH` | `409 Conflict` | Submitted remediation plan hash does not match server verification. |
| `RATE_LIMIT_EXCEEDED` | `429 Too Many Req` | Rate limit exceeded. Includes `Retry-After` header. |
| `INTERNAL_SERVER_ERROR` | `500 Internal Error`| Unhandled server exception. Details suppressed to prevent information leakage. |

---

## 2. Authentication & User Management Endpoints

### 2.1 Register User
- **Method / Path**: `POST /api/auth/register`
- **Auth Level**: Public
- **Request Body**:
  ```json
  {
    "name": "Jane Doe",
    "email": "jane@example.com",
    "password": "SecurePassword123!"
  }
  ```
- **Success Response (`201 Created`)**:
  ```json
  {
    "id": "usr-123e4567-e89b-12d3-a456-426614174000",
    "name": "Jane Doe",
    "email": "jane@example.com",
    "role": "user"
  }
  ```
- **Error Responses**: `400 Bad Request` (weak password), `409 Conflict` (email already exists).

### 2.2 User Login
- **Method / Path**: `POST /api/auth/login`
- **Auth Level**: Public
- **Request Body**:
  ```json
  {
    "email": "jane@example.com",
    "password": "SecurePassword123!"
  }
  ```
- **Success Response (`200 OK`)**:
  - Sets `Set-Cookie: vulnify_session=<token>; HttpOnly; SameSite=Lax; Path=/`
  - Body: Returns user profile JSON.
- **Error Responses**: `401 Unauthorized` (`INVALID_CREDENTIALS`), `429 Too Many Requests`.

### 2.3 Get Current User Session
- **Method / Path**: `GET /api/auth/me`
- **Auth Level**: Authenticated User
- **Success Response (`200 OK`)**:
  ```json
  {
    "id": "usr-123e4567-e89b-12d3-a456-426614174000",
    "name": "Jane Doe",
    "email": "jane@example.com",
    "role": "user"
  }
  ```
- **Error Response**: `401 Unauthorized` (`AUTHENTICATION_REQUIRED`).

### 2.4 User Logout
- **Method / Path**: `POST /api/auth/logout`
- **Auth Level**: Authenticated User
- **Success Response (`200 OK`)**:
  - Clears `vulnify_session` cookie (`Max-Age=0`).
  - Body: `{"message": "Logged out successfully."}`

---

## 3. Health & System Diagnostics

### 3.1 Application Health
- **Method / Path**: `GET /api/health`
- **Auth Level**: Public
- **Success Response (`200 OK`)**:
  ```json
  {
    "status": "healthy",
    "version": "0.2.0"
  }
  ```

### 3.2 Database Health Check
- **Method / Path**: `GET /api/health/db`
- **Auth Level**: Public
- **Success Response (`200 OK`)**:
  ```json
  {
    "status": "connected",
    "database": "FalkorDB",
    "graph": "vulnify"
  }
  ```
- **Error Response (`503 Service Unavailable`)**: When FalkorDB is unreachable.

---

## 4. Projects Management

### 4.1 List Projects
- **Method / Path**: `GET /api/projects`
- **Auth Level**: Authenticated User
- **Success Response (`200 OK`)**: Array of project objects:
  ```json
  [
    {
      "id": "prj-ecommerce-prod",
      "name": "E-Commerce Core",
      "created_at": "2026-10-18T12:00:00Z",
      "service_count": 4,
      "vulnerability_count": 12
    }
  ]
  ```

### 4.2 Create Project
- **Method / Path**: `POST /api/projects`
- **Auth Level**: Authenticated User
- **Request Body**:
  ```json
  {
    "name": "Payment Gateway Service",
    "description": "Production PCI payment processing microservices"
  }
  ```
- **Success Response (`201 Created`)**: Created project object.

### 4.3 Get Project Detail & Topology
- **Method / Path**: `GET /api/projects/{project_id}`
- **Auth Level**: Authenticated User
- **Success Response (`200 OK`)**: Project metadata and aggregated risk score.

### 4.4 Get Project Graph (Explorer Canvas Data)
- **Method / Path**: `GET /api/projects/{project_id}/graph`
- **Auth Level**: Authenticated User
- **Query Parameters**:
  - `include_advisories`: boolean (default `true`)
  - `depth_limit`: integer (default `8`, max `8`)
- **Success Response (`200 OK`)**:
  ```json
  {
    "nodes": [
      { "id": "srv-api-gateway", "label": "Service", "properties": { "name": "api-gateway", "public": true } },
      { "id": "pkg-lodash@4.17.15", "label": "PackageVersion", "properties": { "name": "lodash", "version": "4.17.15" } }
    ],
    "edges": [
      { "id": "rel-1", "source": "srv-api-gateway", "target": "pkg-lodash@4.17.15", "type": "DEPENDS_ON" }
    ]
  }
  ```

---

## 5. Dependency Ingestion Pipeline

### 5.1 Import Dependencies (Lockfile Upload)
- **Method / Path**: `POST /api/projects/{project_id}/dependencies/import`
- **Auth Level**: Authenticated User
- **Content-Type**: `multipart/form-data`
- **Form Fields**:
  - `file`: Uploaded file (`package-lock.json`, `Cargo.lock`, `requirements.txt`, `go.mod`, etc.)
  - `service_name`: string (e.g., `auth-service`)
  - `environment`: string (`production` or `development`, default `production`)
  - `public_facing`: boolean (default `true`)
- **Success Response (`200 OK`)**:
  ```json
  {
    "job_id": "job-987e6543-b21a-43d2-c567-890123456789",
    "service_id": "srv-auth-service",
    "packages_imported": 242,
    "relationships_created": 315,
    "advisories_matched": 4,
    "sha256_hash": "a1b2c3d4..."
  }
  ```

### 5.2 List Ingestion Jobs
- **Method / Path**: `GET /api/projects/{project_id}/dependencies/jobs`
- **Auth Level**: Authenticated User
- **Success Response (`200 OK`)**: Array of ingestion job statuses.

---

## 6. Vulnerability Findings & Exposure Paths

### 6.1 List Findings
- **Method / Path**: `GET /api/projects/{project_id}/findings`
- **Auth Level**: Authenticated User
- **Query Parameters**:
  - `priority`: string (e.g., `P0`, `P1`, `P2`, `P3`)
  - `status`: string (`unreviewed`, `accepted`, `mitigating`, `remediated`)
  - `limit`: integer (default: 50, max: 200)
  - `offset`: integer (default: 0)
- **Success Response (`200 OK`)**: Paginated findings list with deterministic priority bands.

### 6.2 Get Finding Summary & Metrics
- **Method / Path**: `GET /api/projects/{project_id}/findings/summary`
- **Auth Level**: Authenticated User
- **Success Response (`200 OK`)**: Breakdown of findings by severity, priority band, and reachability.

### 6.3 Get Finding Detail
- **Method / Path**: `GET /api/projects/{project_id}/findings/{finding_id}`
- **Auth Level**: Authenticated User
- **Success Response (`200 OK`)**: Finding metadata, CVSS vector, affected versions, advisory references, and triage status.

### 6.4 Finding Exposure Paths
- **Method / Path**: `GET /api/projects/{project_id}/findings/{finding_id}/paths`
- **Auth Level**: Authenticated User
- **Query Parameters**:
  - `limit`: integer (default: 5, max: 20)
- **Success Response (`200 OK`)**:
  ```json
  {
    "finding_id": "fnd-lodash-proto-pollute",
    "paths": [
      {
        "depth": 2,
        "entry_service": "api-gateway",
        "nodes": ["api-gateway", "express@4.18.2", "lodash@4.17.15"],
        "relationships": ["DEPENDS_ON", "DEPENDS_ON"]
      }
    ]
  }
  ```

### 6.5 Record Triage Decision
- **Method / Path**: `POST /api/projects/{project_id}/findings/{finding_id}/triage`
- **Auth Level**: Authenticated User
- **Request Body**:
  ```json
  {
    "status": "mitigating",
    "reason": "Upgrade scheduled in Sprint 42",
    "comment": "Safe patch candidate identified."
  }
  ```
- **Success Response (`200 OK`)**: Updated triage record with author and timestamp.

---

## 7. Fix Simulation & Upgrade Candidates

### 7.1 Get Upgrade Candidates
- **Method / Path**: `GET /api/projects/{project_id}/findings/{finding_id}/upgrade-candidates`
- **Auth Level**: Authenticated User
- **Success Response (`200 OK`)**:
  ```json
  {
    "package_name": "lodash",
    "installed_version": "4.17.15",
    "candidates": [
      { "type": "patch", "version": "4.17.21", "is_vulnerable": false, "breaking_risk": "low" },
      { "type": "minor", "version": "4.18.0", "is_vulnerable": false, "breaking_risk": "medium" }
    ]
  }
  ```

### 7.2 Simulate Fix Impact
- **Method / Path**: `POST /api/projects/{project_id}/remediation/simulate-fix`
- **Auth Level**: Authenticated User
- **Request Body**:
  ```json
  {
    "package_name": "lodash",
    "target_version": "4.17.21"
  }
  ```
- **Success Response (`200 OK`)**:
  ```json
  {
    "target_package": "lodash",
    "from_version": "4.17.15",
    "to_version": "4.17.21",
    "advisories_resolved": 3,
    "remaining_advisories": 0,
    "affected_services": ["api-gateway", "auth-service"],
    "breaking_changes_detected": false
  }
  ```

---

## 8. Human-in-the-Loop GitHub Remediation

### 8.1 Preview Remediation Issue
- **Method / Path**: `POST /api/projects/{project_id}/remediation/github/preview-issue`
- **Auth Level**: Authenticated User
- **Request Body**:
  ```json
  {
    "finding_id": "fnd-lodash-proto-pollute",
    "target_version": "4.17.21"
  }
  ```
- **Success Response (`200 OK`)**:
  ```json
  {
    "title": "fix(deps): Upgrade lodash to 4.17.21 to resolve GHSA-p6mc-m468-83gw",
    "body": "## Vulnerability Remediation\n\n### Summary...",
    "labels": ["security", "vulnify-remediation", "dependencies"],
    "plan_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
  ```

### 8.2 Create Remediation Issue (Write-Gated)
- **Method / Path**: `POST /api/projects/{project_id}/remediation/github/issues`
- **Auth Level**: Authenticated User
- **Request Body**:
  ```json
  {
    "plan_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "approved": true
  }
  ```
- **Success Response (`201 Created`)**:
  ```json
  {
    "status": "created",
    "issue_url": "https://github.com/vulnify/demo-workspace/issues/42",
    "issue_number": 42
  }
  ```
- **Error Responses**: `409 Conflict` (`PLAN_HASH_MISMATCH` - plan modified or expired), `403 Forbidden` (missing token).

---

## 9. AI Agentic Investigation (SSE Streaming)

### 9.1 Stream Investigation
- **Method / Path**: `POST /api/projects/{project_id}/agent/investigate`
- **Auth Level**: Authenticated User
- **Headers**:
  - `Accept: text/event-stream`
  - `X-Requested-With: vulnify`
- **Request Body**:
  ```json
  {
    "finding_id": "fnd-lodash-proto-pollute",
    "user_prompt": "Investigate architectural exposure and check if public services are impacted."
  }
  ```
- **Response**: Server-Sent Events stream (`200 OK`, `Content-Type: text/event-stream`).

#### SSE Event Protocol
The stream emits sequential JSON payloads prefixed with `data: `:

1. **`step` event**: Describes the agent's current stage of reasoning.
   ```
   data: {"type": "step", "content": "Querying FalkorDB for dependency exposure paths..."}
   ```
2. **`tool_call` event**: Informs the client of a FastMCP tool invocation.
   ```
   data: {"type": "tool_call", "tool": "get_dependency_paths", "inputs": {"service_id": "srv-api-gateway", "target_id": "pkg-lodash@4.17.15"}}
   ```
3. **`tool_result` event**: Returns the tool's verified output.
   ```
   data: {"type": "tool_result", "tool": "get_dependency_paths", "summary": "Found 1 path at depth 2"}
   ```
4. **`answer` event**: Final synthesized conclusion and remediation advice.
   ```
   data: {"type": "answer", "content": "Lodash 4.17.15 is reached from public api-gateway...", "priority": "P0"}
   ```
5. **`done` event**: Closes the investigation run.
   ```
   data: {"type": "done", "run_id": "run-abc1234"}
   ```

---

## 10. Admin & Integration Settings

### 10.1 Get GitHub Integration Config
- **Method / Path**: `GET /api/admin/github-config`
- **Auth Level**: **Admin Only**
- **Success Response (`200 OK`)**: Token status (masked), default owner, default repo.

### 10.2 Update GitHub Integration Config
- **Method / Path**: `PUT /api/admin/github-config`
- **Auth Level**: **Admin Only**
- **Request Body**:
  ```json
  {
    "token": "ghp_securePersonalAccessTokenHere",
    "default_owner": "my-enterprise-org",
    "default_repo": "security-remediation"
  }
  ```
- **Success Response (`200 OK`)**: Updated configuration status.
