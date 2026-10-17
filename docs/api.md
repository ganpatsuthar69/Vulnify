# Vulnify API Contract

## Standardized API Error Response Format (US-004)

All API error responses across Vulnify follow a unified JSON schema:

```json
{
  "code": "PROJECT_NOT_FOUND",
  "message": "The requested project was not found.",
  "request_id": "req-abc123"
}
```

- **`code`**: Stable, machine-readable identifier (e.g. `INVALID_CREDENTIALS`, `AUTHENTICATION_REQUIRED`, `FORBIDDEN`, `CSRF_ERROR`, `NOT_FOUND`, `METHOD_NOT_ALLOWED`, `CONFLICT`, `VALIDATION_ERROR`, `RATE_LIMIT_EXCEEDED`, `INTERNAL_SERVER_ERROR`).
- **`message`**: Safe, human-readable error description that does not leak internal traces or confidential information.
- **`request_id`**: Unique request identifier, also propagated in the `X-Request-ID` HTTP response header and structured backend logs for end-to-end diagnostics.

---

## Authentication & User Management Endpoints

All authenticated endpoints use cookie-based session management (`httpOnly` session cookie named `vulnify_session`). State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) require the `X-Requested-With: vulnify` header and validate the `Origin` header to prevent CSRF attacks. Every response includes the `X-Request-ID` header.

---

### 1. `POST /api/auth/register`

Registers a new user account with default `user` role and issues an `httpOnly` session cookie upon success.

#### Request
- **Method**: `POST`
- **Path**: `/api/auth/register`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Body**:
  ```json
  {
    "name": "Jane Doe",
    "email": "jane@example.com",
    "password": "<min_8_chars_password>"
  }
  ```

#### Responses
- **`201 Created`**: User registered and authenticated.
  - **Headers**:
    - `Set-Cookie: vulnify_session=<token>; HttpOnly; SameSite=Lax; Path=/`
    - `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "id": "uuid-v4-string",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "role": "user"
    }
    ```
- **`409 Conflict`**: An account with this email address already exists.
  - **Headers**: `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "code": "CONFLICT",
      "message": "An account with this email already exists.",
      "request_id": "<request_id>"
    }
    ```
- **`422 Unprocessable Entity`**: Validation failure (short password, invalid email format, empty name).
  - **Headers**: `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "code": "VALIDATION_ERROR",
      "message": "password: String should have at least 8 characters.",
      "request_id": "<request_id>"
    }
    ```

---

### 2. `POST /api/auth/login`

Authenticates a registered user with email and password and issues an `httpOnly` session cookie upon success.

#### Request
- **Method**: `POST`
- **Path**: `/api/auth/login`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Body**:
  ```json
  {
    "email": "jane@example.com",
    "password": "<user_password>"
  }
  ```

#### Responses
- **`200 OK`**: Successfully authenticated.
  - **Headers**:
    - `Set-Cookie: vulnify_session=<token>; HttpOnly; SameSite=Lax; Path=/`
    - `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "id": "uuid-v4-string",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "role": "user"
    }
    ```
- **`401 Unauthorized`**: Invalid email or password.
  - **Headers**: `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "code": "INVALID_CREDENTIALS",
      "message": "Invalid email or password.",
      "request_id": "<request_id>"
    }
    ```
- **`429 Too Many Attempts`**: Rate limit exceeded (5 failed logins per 15 minutes).
  - **Headers**:
    - `Retry-After: <seconds>` (integer)
    - `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "code": "RATE_LIMIT_EXCEEDED",
      "message": "Too many attempts. Try again in 900s.",
      "request_id": "<request_id>"
    }
    ```

---

### 3. `GET /api/auth/me`

Retrieves the currently authenticated user's profile.

#### Request
- **Method**: `GET`
- **Path**: `/api/auth/me`
- **Credentials**: `include` (transmits `httpOnly` session cookie)

#### Responses
- **`200 OK`**: Valid session.
  - **Headers**: `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "id": "uuid-v4-string",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "role": "user"
    }
    ```
- **`401 Unauthorized`**: Missing, expired, or invalid session cookie.
  - **Headers**: `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "code": "AUTHENTICATION_REQUIRED",
      "message": "Authentication required.",
      "request_id": "<request_id>"
    }
    ```

---

### 4. `POST /api/auth/logout`

Terminates the active user session and clears the session cookie.

#### Request
- **Method**: `POST`
- **Path**: `/api/auth/logout`
- **Headers**:
  - `X-Requested-With: vulnify`
- **Credentials**: `include`

#### Responses
- **`204 No Content`**: Session revoked and cookie deleted.

---

### 5. `POST /api/admin/promote`

Admin-only route to update a registered user's role (e.g. promote to `admin`).

#### Request
- **Method**: `POST`
- **Path**: `/api/admin/promote`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Credentials**: `include`
- **Body**:
  ```json
  {
    "email": "jane@example.com",
    "role": "admin"
  }
  ```

#### Responses
- **`200 OK`**: Role updated.
  - **Headers**: `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "id": "uuid-v4-string",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "role": "admin"
    }
    ```
- **`403 Forbidden`**: Authenticated user is not an administrator.
  - **Headers**: `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "code": "FORBIDDEN",
      "message": "Administrator access required.",
      "request_id": "<request_id>"
    }
    ```
- **`404 Not Found`**: Target user email does not exist.
  - **Headers**: `X-Request-ID: <request_id>`
  - **Body**:
    ```json
    {
      "code": "NOT_FOUND",
      "message": "User not found.",
      "request_id": "<request_id>"
    }
    ```

---

## Project Management Endpoints (US-101)

All project endpoints require authentication via the session cookie (`httpOnly` session cookie named `vulnify_session`). State-changing requests (`POST`, `PUT`, `DELETE`) require the `X-Requested-With: vulnify` header and validate the `Origin` header.

---

### 6. `GET /api/projects`

Retrieves all projects available to the authenticated user, ordered by creation date descending.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects`
- **Credentials**: `include`

#### Responses
- **`200 OK`**: List of projects (empty array `[]` when no projects exist).
  - **Body**:
    ```json
    [
      {
        "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "name": "Payment Service",
        "ecosystem": "npm",
        "description": "Payment application dependencies",
        "created_at": 1729170000
      }
    ]
    ```
- **`401 Unauthorized`**: Authentication required.

---

### 7. `POST /api/projects`

Creates and persists a new project node in FalkorDB. Project names are validated for case-insensitive uniqueness.

#### Request
- **Method**: `POST`
- **Path**: `/api/projects`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Credentials**: `include`
- **Body**:
  ```json
  {
    "name": "Payment Service",
    "ecosystem": "npm",
    "description": "Payment application dependencies"
  }
  ```

#### Validation Rules
- `name`: Required, non-empty, trimmed string between 1 and 100 characters. Unique (case-insensitive).
- `ecosystem`: Required, must be one of the supported package ecosystems (`npm`, `PyPI`).
- `description`: Optional string up to 500 characters.

#### Responses
- **`201 Created`**: Project created and persisted in FalkorDB.
  - **Body**:
    ```json
    {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "name": "Payment Service",
      "ecosystem": "npm",
      "description": "Payment application dependencies",
      "created_at": 1729170000
    }
    ```
- **`401 Unauthorized`**: Authentication required.
- **`403 Forbidden`**: Missing or invalid `X-Requested-With` header or untrusted origin.
- **`409 Conflict`**: A project with this name already exists.
  - **Body**:
    ```json
    {
      "code": "CONFLICT",
      "message": "A project with this name already exists.",
      "request_id": "<request_id>"
    }
    ```
- **`422 Unprocessable Entity`**: Request validation error (missing required fields, empty name, unsupported ecosystem, invalid format).

---

### 8. `GET /api/projects/{project_id}`

Retrieves details of a specific project by its unique ID.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}`
- **Credentials**: `include`

#### Responses
- **`200 OK`**: Project details.
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

### 9. `GET /api/projects/ecosystems`

Retrieves the list of supported package ecosystems.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/ecosystems`
- **Credentials**: `include`

#### Responses
- **`200 OK`**:
  ```json
  {
    "supported_ecosystems": ["npm", "PyPI"]
  }
  ```
- **`401 Unauthorized`**: Authentication required.

---

## Dependency Ingestion Endpoints (US-102)

### 10. `POST /api/projects/{project_id}/dependencies/import`

Imports and persists a real project's dependency graph in FalkorDB for a named service from a supported lockfile.

#### Authentication & Headers
- **Authentication**: `httpOnly` session cookie (`vulnify_session`).
- **Required Header**: `X-Requested-With: vulnify`.
- **Supported Content-Types**:
  - `multipart/form-data` (recommended for browser uploads):
    - `service_name` (string, required): Service name within project (`^[a-zA-Z0-9_.-]+$`, max 100 characters).
    - `file` (file binary, required): Lockfile binary content.
  - `application/json`:
    - `service_name` (string, required): Service name.
    - `filename` (string, required): Lockfile filename (e.g. `package-lock.json`).
    - `content` (string, required): UTF-8 encoded text of the lockfile.

#### Ecosystem and Format Support
- **Supported Ecosystem**: `npm`.
- **Supported Format**: `package-lock.json` (npm lockfile versions 1, 2, and 3).
- **Format Verification**: File format must match the referenced project's declared ecosystem (`npm`). Non-matching ecosystems or unsupported extensions are rejected.
- **Maximum File Size**: 10 MB (configurable via `MAX_UPLOAD_SIZE_BYTES` in backend settings). Uploads exceeding this limit are rejected before unbounded parsing.

#### No-Execution Guarantee
Uploaded lockfiles are parsed deterministically as data structures via standard JSON parsing. No lifecycle scripts, eval expressions, or external shell commands are executed.

#### Graph Schema & Idempotency
- Nodes created:
  - `(:Project)-[:HAS_SERVICE]->(:Service {id: "<project_id>:<service_name>", name: "<service_name>"})`
  - `(:PackageVersion {id: "npm:<name>@<version>", name: "<name>", version: "<version>", ecosystem: "npm", purl: "pkg:npm/<name>@<version>"})`
  - `(:ImportEvent {id, project_id, service_id, filename, sha256_hash, packages_count, edges_count, imported_at, status})`
- Edges created:
  - `(:Service)-[:DEPENDS_ON {direct: true, origin: 'manifest'}]->(:PackageVersion)`
  - `(:PackageVersion)-[:DEPENDS_ON {direct: false, origin: 'manifest'}]->(:PackageVersion)`
  - `(:Service)-[:IMPORTED_FROM]->(:ImportEvent)`
- **Idempotency Guarantee**: All nodes and relationships use parameterized Cypher `MERGE`. Reimporting the exact same lockfile creates zero duplicate nodes or edges and returns accurate `reused` counts.

#### Responses

- **`200 OK`**: Lockfile successfully parsed and stored.
  - **Body**:
    ```json
    {
      "project_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "service_name": "payment-api",
      "filename": "package-lock.json",
      "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "packages_parsed": 52,
      "packages_created": 52,
      "packages_reused": 0,
      "edges_created": 84,
      "edges_reused": 0,
      "skipped_entries": 0,
      "warnings": [],
      "errors": [],
      "status": "completed",
      "imported_at": 1729170000
    }
    ```
- **`401 Unauthorized`**: Authentication required.
- **`403 Forbidden`**: Missing `X-Requested-With` header or untrusted origin.
- **`404 Not Found`**: Referenced project does not exist.
  - **Body**:
    ```json
    {
      "code": "NOT_FOUND",
      "message": "Project not found.",
      "request_id": "<request_id>"
    }
    ```
- **`413 Content Too Large`**: File size exceeds the maximum allowed limit of 10 MB.
- **`415 Unsupported Media Type`**: Content-Type is not `multipart/form-data` or `application/json`.
- **`422 Unprocessable Entity`**: Validation failure (empty service name, invalid characters, unsupported lockfile format, empty file, or malformed JSON).
  - **Body**:
    ```json
    {
      "code": "VALIDATION_ERROR",
      "message": "Unsupported lockfile format 'poetry.lock'. Supported format for npm projects is 'package-lock.json'.",
      "request_id": "<request_id>"
    }
    ```
- **`500 Internal Server Error`**: Database error. Details are sanitized to avoid leaking Cypher queries or driver traces.

---

### 8. `POST /api/projects/{project_id}/advisories/import`

Triggers vulnerability advisory ingestion from the official Open Source Vulnerabilities (OSV) API (`https://api.osv.dev`) for all package versions imported into the specified project.

#### Request
- **Method**: `POST`
- **Path**: `/api/projects/{project_id}/advisories/import`
- **Query Parameters**:
  - `force_refresh` (boolean, optional, default: `false`): When `true`, bypasses cache and queries upstream OSV directly.
- **Headers**:
  - `X-Requested-With: vulnify`

#### Workflow & Resilience
1. Retrieves all `PackageVersion` nodes connected to the project via `(Project)-[:HAS_SERVICE]->(Service)-[:DEPENDS_ON*1..15]->(PackageVersion)`.
2. Deduplicates packages by `(ecosystem, name, version)`.
3. Checks local in-memory TTL cache (`OSV_CACHE_TTL_SECONDS`). Confirmed no-match results are cached to prevent redundant lookups.
4. Executes batched queries against `POST /v1/querybatch` (batch size controlled by `OSV_BATCH_SIZE`).
5. In case of transient network errors or HTTP 429/503 responses, applies exponential backoff with jitter and respects `Retry-After` headers (up to `OSV_API_MAX_RETRIES`).
6. Falls back to individual queries `POST /v1/query` on partial batch failures.
7. Persists `(:Vulnerability)` nodes with deterministic IDs (`v.id = advisory.id`) and creates bidirectional relationships `(pv)-[:HAS_ADVISORY]->(v)` and `(v)-[:AFFECTS]->(pv)`.
8. Returns a truthful summary of lookups, cache hits, advisories found, created, updated, and failures.

#### Responses
- **`200 OK`**: Advisory ingestion executed.
  - **Body**:
    ```json
    {
      "project_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "total_package_versions": 45,
      "eligible_package_versions": 45,
      "unique_lookups": 32,
      "cache_hits": 10,
      "advisories_found": 3,
      "advisories_created": 3,
      "advisories_updated": 0,
      "relationships_created": 3,
      "relationships_reused": 0,
      "packages_with_no_advisories": 29,
      "skipped_packages": 0,
      "failed_lookups": 0,
      "status": "completed",
      "errors": [],
      "duration_ms": 342.5
    }
    ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

### 9. `GET /api/projects/{project_id}/advisories`

Lists all vulnerability advisories currently linked to package versions in the project.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/advisories`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**: List of advisories.
  - **Body**:
    ```json
    [
      {
        "id": "GHSA-1234-5678-90ab",
        "summary": "Prototype pollution in lodash",
        "details": "A prototype pollution vulnerability allows remote code execution.",
        "severity": "CRITICAL",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "aliases": ["CVE-2023-99999"],
        "published": "2023-01-15T00:00:00Z",
        "modified": "2023-01-16T00:00:00Z",
        "source_url": "https://osv.dev/vulnerability/GHSA-1234-5678-90ab",
        "retrieved_at": 1729170000,
        "package_version_id": "npm:lodash@4.17.20",
        "package_name": "lodash",
        "package_version": "4.17.20",
        "ecosystem": "npm"
      }
    ]
    ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

## Ecosystem-Aware Version Matching Endpoints (US-104)

### 10. `POST /api/projects/{project_id}/vulnerabilities/match`

Evaluates all package-advisory pairs associated with a project using ecosystem-aware version comparison semantics (npm SemVer 2.0.0 and PyPI PEP 440) and idempotently persists `(v:Vulnerability)-[:AFFECTS]->(pv:PackageVersion)` relationships in FalkorDB with explainable match reasons.

#### Request
- **Method**: `POST`
- **Path**: `/api/projects/{project_id}/vulnerabilities/match`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**: Version matching completed.
  - **Body**:
    ```json
    {
      "project_id": "proj-uuid-1",
      "total_evaluated": 12,
      "affected_count": 2,
      "not_affected_count": 10,
      "unknown_count": 0,
      "relationships_persisted": 2,
      "relationships_removed": 0,
      "duration_ms": 14.8,
      "status": "completed",
      "results": [
        {
          "package_name": "lodash",
          "package_version": "4.17.20",
          "ecosystem": "npm",
          "advisory_id": "GHSA-29mw-wpgm-hmr9",
          "status": "affected",
          "reason_code": "WITHIN_AFFECTED_RANGE",
          "reason": "Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-29mw-wpgm-hmr9.",
          "matched_range": "< 4.17.21",
          "fixed_version": "4.17.21",
          "comparator": "semver",
          "evaluated_at": 1729172000,
          "fingerprint": "8f8b5f3d4...64chars"
        }
      ]
    }
    ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

### 11. `GET /api/projects/{project_id}/vulnerabilities`

Retrieves all confirmed affected vulnerability findings and their version match explanations for a project.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/vulnerabilities`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**: List of vulnerability findings.
  - **Body**:
    ```json
    [
      {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
        "details": "All versions of package lodash prior to 4.17.21 are vulnerable...",
        "severity": "HIGH",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "aliases": ["CVE-2020-28500"],
        "published": "2021-02-15T00:00:00Z",
        "modified": "2021-02-16T00:00:00Z",
        "source_url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
        "package_version_id": "npm:lodash@4.17.20",
        "package_name": "lodash",
        "package_version": "4.17.20",
        "ecosystem": "npm",
        "match_status": "affected",
        "match_reason": "Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-29mw-wpgm-hmr9.",
        "reason_code": "WITHIN_AFFECTED_RANGE",
        "matched_range": "< 4.17.21",
        "fixed_version": "4.17.21",
        "evaluated_at": 1729172000,
        "comparator": "semver",
        "fingerprint": "8f8b5f3d4...64chars"
      }
    ]
    ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

### 12. `POST /api/vulnerabilities/evaluate`

Evaluates an individual package version against an OSV advisory payload on demand without requiring project-scoped persistence.

#### Request
- **Method**: `POST`
- **Path**: `/api/vulnerabilities/evaluate`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Body**:
  ```json
  {
    "package_name": "lodash",
    "package_version": "4.17.20",
    "ecosystem": "npm",
    "advisory": {
      "id": "GHSA-29mw-wpgm-hmr9",
      "summary": "ReDoS in lodash",
      "affected": [
        {
          "package": {"ecosystem": "npm", "name": "lodash"},
          "ranges": [
            {
              "type": "SEMVER",
              "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]
            }
          ]
        }
      ]
    }
  }
  ```

#### Responses
- **`200 OK`**: Evaluation result.
  - **Body**:
    ```json
    {
      "package_name": "lodash",
      "package_version": "4.17.20",
      "ecosystem": "npm",
      "advisory_id": "GHSA-29mw-wpgm-hmr9",
      "status": "affected",
      "reason_code": "WITHIN_AFFECTED_RANGE",
      "reason": "Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-29mw-wpgm-hmr9.",
      "matched_range": "< 4.17.21",
      "fixed_version": "4.17.21",
      "comparator": "semver",
      "evaluated_at": 1729172000,
      "fingerprint": "8f8b5f3d4...64chars"
    }
    ```
- **`401 Unauthorized`**: Authentication required.
- **`422 Unprocessable Entity`**: Invalid request body.



