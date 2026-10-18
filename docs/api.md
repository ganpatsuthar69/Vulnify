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
- `ecosystem`: Required, must be one of the supported package ecosystems (`npm`, `PyPI`, `Cargo`, `Go`).
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

### 9. `GET /api/projects/ecosystem-capabilities`

Retrieves the backend-owned capability registry defining all genuinely implemented ecosystems, import methods, accepted file formats, paired-file requirements, fidelity ratings, and field definitions.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/ecosystem-capabilities`
- **Credentials**: `include`

#### Responses
- **`200 OK`**:
  ```json
  {
    "supported_ecosystems": ["npm", "PyPI", "Cargo", "Go"],
    "capabilities": [
      {
        "id": "npm",
        "display_name": "npm (JavaScript / Node.js)",
        "osv_ecosystem": "npm",
        "max_file_size_bytes": 10485760,
        "max_packages": 5000,
        "validation_rules": [
          "Valid UTF-8 JSON",
          "package-lock.json v1, v2, or v3",
          "npm-shrinkwrap.json format"
        ],
        "limitations": [
          "Does not execute lifecycle scripts or npm install",
          "Peer dependency resolution follows locked graph strictly"
        ],
        "supported_import_methods": [
          {
            "id": "npm_lockfile",
            "name": "npm package-lock.json",
            "description": "Resolved dependency tree from an npm package-lock.json or npm-shrinkwrap.json file.",
            "fidelity": "exact_lockfile",
            "fidelity_description": "Extracts exact resolved versions and direct/transitive dependency edges from locked trees.",
            "accepted_filenames": ["package-lock.json", "npm-shrinkwrap.json"],
            "accepted_extensions": [".json"],
            "requires_paired_file": false,
            "fields": [
              {
                "name": "service_name",
                "label": "Service Name",
                "type": "string",
                "required": true,
                "description": "Named microservice or application component."
              },
              {
                "name": "file",
                "label": "Dependency File",
                "type": "file",
                "required": true,
                "description": "Primary lockfile (package-lock.json)."
              }
            ],
            "limitations": [
              "Requires package-lock.json schema versions 1, 2, or 3."
            ]
          }
        ]
      },
      {
        "id": "PyPI",
        "display_name": "PyPI (Python)",
        "osv_ecosystem": "PyPI",
        "max_file_size_bytes": 10485760,
        "max_packages": 5000,
        "validation_rules": [
          "Valid TOML (poetry.lock, uv.lock, pylock.toml)",
          "Valid requirements.txt format with pinned == dependencies"
        ],
        "limitations": [
          "setup.py or pyproject.toml without lockfile is not accepted without pre-resolution",
          "requirements.txt with unbounded version ranges skips unpinned packages with explicit warnings"
        ],
        "supported_import_methods": [
          {
            "id": "poetry_lock",
            "name": "Poetry Lockfile (poetry.lock)",
            "description": "Fully resolved dependency tree from Poetry.",
            "fidelity": "exact_lockfile",
            "fidelity_description": "Extracts exact resolved package versions, files hashes, and dependency edges.",
            "accepted_filenames": ["poetry.lock"],
            "accepted_extensions": [".lock"],
            "requires_paired_file": false,
            "fields": [],
            "limitations": []
          },
          {
            "id": "uv_lock",
            "name": "uv Lockfile (uv.lock)",
            "description": "Modern Python dependency lockfile generated by Astral uv.",
            "fidelity": "exact_lockfile",
            "fidelity_description": "Extracts exact resolved package versions, wheels, and dependency edges.",
            "accepted_filenames": ["uv.lock"],
            "accepted_extensions": [".lock"],
            "requires_paired_file": false,
            "fields": [],
            "limitations": []
          },
          {
            "id": "pylock_toml",
            "name": "PEP 751 Lockfile (pylock.toml)",
            "description": "Standardized Python dependency lockfile adhering to PEP 751.",
            "fidelity": "exact_lockfile",
            "fidelity_description": "Extracts exact pinned package versions and hashes.",
            "accepted_filenames": ["pylock.toml"],
            "accepted_extensions": [".toml"],
            "requires_paired_file": false,
            "fields": [],
            "limitations": []
          },
          {
            "id": "requirements_txt",
            "name": "Pinned Requirements (requirements.txt)",
            "description": "Declared direct dependencies from a Python requirements file.",
            "fidelity": "manifest_declared",
            "fidelity_description": "Only strictly pinned entries (package==version) provide verifiable exact versions; unpinned constraints or ranges are omitted.",
            "accepted_filenames": ["requirements.txt"],
            "accepted_extensions": [".txt"],
            "requires_paired_file": false,
            "fields": [],
            "limitations": [
              "Only pinned versions (package==X.Y.Z) are imported.",
              "Transitive dependencies are not resolved if absent from the file.",
              "VCS and direct URL references without immutable tags are skipped."
            ]
          }
        ]
      },
      {
        "id": "Cargo",
        "display_name": "Cargo (Rust)",
        "osv_ecosystem": "crates.io",
        "max_file_size_bytes": 10485760,
        "max_packages": 5000,
        "validation_rules": [
          "Valid UTF-8 TOML Cargo.lock v1-v4"
        ],
        "limitations": [
          "Cargo.toml manifest without Cargo.lock is not accepted (manifest declared fidelity requires lockfile)"
        ],
        "supported_import_methods": [
          {
            "id": "cargo_lock",
            "name": "Cargo Lockfile (Cargo.lock)",
            "description": "Fully resolved dependency graph from Rust Cargo package manager.",
            "fidelity": "exact_lockfile",
            "fidelity_description": "Extracts exact crate versions, checksums, and dependency edges.",
            "accepted_filenames": ["Cargo.lock"],
            "accepted_extensions": [".lock"],
            "requires_paired_file": false,
            "fields": [],
            "limitations": []
          }
        ]
      },
      {
        "id": "Go",
        "display_name": "Go (Golang)",
        "osv_ecosystem": "Go",
        "max_file_size_bytes": 10485760,
        "max_packages": 5000,
        "validation_rules": [
          "Valid UTF-8 go.mod directives"
        ],
        "limitations": [
          "Inter-module transitive edges are resolved via Go module semantics; direct vs indirect dependencies are classified"
        ],
        "supported_import_methods": [
          {
            "id": "go_mod",
            "name": "Go Module (go.mod with optional go.sum)",
            "description": "Go module dependencies from go.mod with optional paired checksum verification from go.sum.",
            "fidelity": "exact_lockfile",
            "fidelity_description": "Extracts module versions and verifies module checksums if go.sum is supplied.",
            "accepted_filenames": ["go.mod"],
            "accepted_extensions": [".mod"],
            "requires_paired_file": false,
            "paired_file_name": "go.sum",
            "paired_file_description": "Optional paired go.sum file for cryptographic module verification.",
            "fields": [],
            "limitations": []
          }
        ]
      }
    ]
  }
  ```
- **`401 Unauthorized`**: Authentication required.

---

### 10. `GET /api/projects/ecosystems`

Retrieves the list of supported package ecosystems.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/ecosystems`
- **Credentials**: `include`

#### Responses
- **`200 OK`**:
  ```json
  {
    "supported_ecosystems": ["npm", "PyPI", "Cargo", "Go"]
  }
  ```
- **`401 Unauthorized`**: Authentication required.



---

### 11. `GET /api/projects/{project_id}/packages`

Retrieves distinct package versions reachable from services belonging to a project in FalkorDB.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/packages`
- **Credentials**: `include`

#### Responses
- **`200 OK`**: List of package versions.
  ```json
  [
    {
      "id": "npm:lodash@4.17.20",
      "name": "lodash",
      "version": "4.17.20",
      "ecosystem": "npm",
      "purl": "pkg:npm/lodash@4.17.20"
    }
  ]
  ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

## Dependency Ingestion Endpoints (US-102 & Multi-Ecosystem)

### 12. `POST /api/projects/{project_id}/dependencies/import`

Imports and persists a real project's dependency graph in FalkorDB for a named service from a supported ecosystem lockfile or manifest.

#### Authentication & Headers
- **Authentication**: `httpOnly` session cookie (`vulnify_session`).
- **Required Header**: `X-Requested-With: vulnify`.
- **Supported Content-Types**:
  - `multipart/form-data` (recommended for browser uploads):
    - `service_name` (string, required): Service name within project (`^[a-zA-Z0-9_.-]+$`, max 100 characters).
    - `file` (file binary, required): Primary lockfile or manifest binary content.
    - `secondary_file` (file binary, optional): Paired checksum or verification file (e.g. `go.sum` for Go).
    - `import_method` (string, optional): Explicit import method identifier matching backend capability (e.g. `poetry_lock`, `uv_lock`, `requirements_txt`, `pylock_toml`, `cargo_lock`, `go_mod`).
  - `application/json`:
    - `service_name` (string, required): Service name.
    - `filename` (string, required): Dependency filename (e.g. `package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.mod`).
    - `content` (string, required): UTF-8 encoded text of the primary file.
    - `secondary_filename` (string, optional): Paired file name (e.g. `go.sum`).
    - `secondary_content` (string, optional): UTF-8 encoded text of the paired file.
    - `import_method` (string, optional): Import method ID.

#### Supported Ecosystems & Implemented Formats
- **npm (JavaScript / Node.js)**:
  - Formats: `package-lock.json` (v1, v2, v3), `npm-shrinkwrap.json`.
  - Fidelity: `exact_lockfile`.
- **PyPI (Python)**:
  - Formats: `poetry.lock` (Poetry), `uv.lock` (Astral uv), `pylock.toml` (PEP 751), `requirements.txt` (pinned `==` dependencies).
  - Fidelity: `exact_lockfile` (Poetry, uv, PEP 751); `manifest_declared` (requirements.txt).
- **Cargo (Rust)**:
  - Formats: `Cargo.lock` (v1-v4).
  - Fidelity: `exact_lockfile`.
- **Go (Golang)**:
  - Formats: `go.mod` (module declarations & `// indirect` classification) with optional paired `go.sum` (cryptographic checksums).
  - Fidelity: `exact_lockfile` / `checksum_verified` when paired with `go.sum`.

#### Bounded Limits & Security Controls
- **Maximum File Size**: 10 MB default (`DEPENDENCY_IMPORT_MAX_FILE_SIZE_MB`, `MAX_UPLOAD_SIZE_BYTES`).
- **Maximum Package Limit**: 5,000 packages per import (`DEPENDENCY_IMPORT_MAX_PACKAGES`).
- **Batch Processing**: Database ingestion batched (`DEPENDENCY_IMPORT_BATCH_SIZE`).
- **No-Execution Guarantee**: Files are parsed deterministically via standard data structure AST parsers (JSON, TOML, directive tokens). Manifest scripts, lifecycle hooks, and shell commands are never executed.

#### Graph Schema & Idempotency
- Nodes created:
  - `(:Project)-[:HAS_SERVICE]->(:Service {id: "<project_id>:<service_name>", name: "<service_name>"})`
  - `(:PackageVersion {id: "<eco>:<name>@<version>", name: "<name>", version: "<version>", ecosystem: "<eco>", purl: "pkg:<eco>/<name>@<version>", checksum: "..."})`
  - `(:ImportEvent {id, project_id, service_id, filename, sha256_hash, packages_count, edges_count, imported_at, status, fidelity, ecosystem, import_method})`
- Edges created:
  - `(:Service)-[:DEPENDS_ON {direct: true, origin: 'manifest'}]->(:PackageVersion)`
  - `(:PackageVersion)-[:DEPENDS_ON {direct: false, origin: 'manifest'}]->(:PackageVersion)`
  - `(:Service)-[:IMPORTED_FROM]->(:ImportEvent)`
- **Idempotency Guarantee**: All nodes and relationships use parameterized Cypher `MERGE`. Reimporting identical files creates zero duplicate nodes or edges and returns accurate `reused` counts.

#### Responses

- **`200 OK`**: Dependency graph successfully parsed and stored.
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
      "imported_at": 1729170000,
      "fidelity": "exact_lockfile",
      "ecosystem": "npm",
      "import_method": "npm_lockfile",
      "secondary_filename": null
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
- **`413 Content Too Large`**: File size exceeds the maximum allowed limit.
- **`415 Unsupported Media Type`**: Content-Type is not `multipart/form-data` or `application/json`.
- **`422 Unprocessable Entity`**: Validation failure (empty service name, invalid characters, unsupported lockfile format, empty file, exceeding package limits, or malformed syntax).
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

---

## Ingestion Jobs & History Endpoints (US-105)

### 13. `GET /api/projects/{project_id}/jobs`

Retrieves a paginated list of historical ingestion jobs for a project, including dependency imports, OSV synchronizations, and version matching runs, sorted chronologically with scoped aggregate summary metrics.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/jobs`
- **Headers**:
  - `X-Requested-With: vulnify`
- **Query Parameters**:
  - `page` (integer, optional, default: `1`, min: `1`): 1-indexed page number.
  - `page_size` (integer, optional, default: `20`, min: `1`, max: `100`): Results per page.
  - `status` (string, optional): Filter by execution status (`queued`, `running`, `succeeded`, `partial`, `failed`).
  - `job_type` (string, optional): Filter by job type (`dependency_import`, `osv_sync`, `version_matching`).
  - `service_name` (string, optional): Filter by case-insensitive partial match on service name.

#### Responses
- **`200 OK`**: Paginated jobs list with aggregate statistics.
  ```json
  {
    "items": [
      {
        "id": "e4b6c310-850f-48d6-a058-29a502bf65d8",
        "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
        "job_type": "dependency_import",
        "status": "succeeded",
        "stage": "Dependency import completed successfully",
        "service_id": "893c5240-a19e-4c55-b8ea-a3d538eec612:api-gateway",
        "service_name": "api-gateway",
        "processed_items": 142,
        "total_items": 142,
        "percentage": 100,
        "discovered_items": 142,
        "created_items": 38,
        "updated_items": 0,
        "reused_items": 104,
        "skipped_items": 0,
        "failed_items": 0,
        "error_summary": null,
        "errors": [],
        "warnings": [],
        "retry_eligible": false,
        "retry_of_job_id": null,
        "created_at": 1729172000,
        "started_at": 1729172000,
        "completed_at": 1729172003,
        "duration_ms": 3120.5,
        "initiated_by": "admin@vulnify.local",
        "filename": "package-lock.json",
        "secondary_filename": null,
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ecosystem": "npm",
        "import_method": "npm_lockfile",
        "fidelity": "exact_lockfile"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 20,
    "total_pages": 1,
    "summary_stats": {
      "total_runs": 1,
      "running_runs": 0,
      "succeeded_runs": 1,
      "failed_runs": 0,
      "partial_runs": 0
    }
  }
  ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.
- **`422 Unprocessable Entity`**: Invalid pagination parameters.

---

### 14. `GET /api/projects/{project_id}/jobs/{job_id}`

Retrieves detailed state, execution stages, provenance records, and error breakdowns for a specific ingestion job.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/jobs/{job_id}`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**: Complete ingestion job record.
  ```json
  {
    "id": "e4b6c310-850f-48d6-a058-29a502bf65d8",
    "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
    "job_type": "dependency_import",
    "status": "succeeded",
    "stage": "Dependency import completed successfully",
    "service_id": "893c5240-a19e-4c55-b8ea-a3d538eec612:api-gateway",
    "service_name": "api-gateway",
    "processed_items": 142,
    "total_items": 142,
    "percentage": 100,
    "discovered_items": 142,
    "created_items": 38,
    "updated_items": 0,
    "reused_items": 104,
    "skipped_items": 0,
    "failed_items": 0,
    "error_summary": null,
    "errors": [],
    "warnings": [],
    "retry_eligible": false,
    "retry_of_job_id": null,
    "created_at": 1729172000,
    "started_at": 1729172000,
    "completed_at": 1729172003,
    "duration_ms": 3120.5,
    "initiated_by": "admin@vulnify.local",
    "filename": "package-lock.json",
    "secondary_filename": null,
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ecosystem": "npm",
    "import_method": "npm_lockfile",
    "fidelity": "exact_lockfile"
  }
  ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Ingestion job not found for project.

---

### 15. `POST /api/projects/{project_id}/jobs/{job_id}/retry`

Retries an eligible failed or partial ingestion job, creating a new execution record linked via `retry_of_job_id` while preserving the original historical audit trail.

#### Request
- **Method**: `POST`
- **Path**: `/api/projects/{project_id}/jobs/{job_id}/retry`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`

#### Constraints
- Only jobs with status `failed` or `partial` and `retry_eligible: true` can be retried.
- For `dependency_import`, retries reject automatic execution with status `400` because raw files are not persisted; the user is prompted to re-upload.
- For `osv_sync` and `version_matching`, a new linked run is executed immediately.

#### Responses
- **`200 OK`**: Retry initiated successfully.
  ```json
  {
    "message": "Job e4b6c310-850f-48d6-a058-29a502bf65d8 successfully retried as a7c2d109-1234-4567-89ab-cdef01234567.",
    "original_job_id": "e4b6c310-850f-48d6-a058-29a502bf65d8",
    "new_job": {
      "id": "a7c2d109-1234-4567-89ab-cdef01234567",
      "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
      "job_type": "osv_sync",
      "status": "succeeded",
      "stage": "Advisory ingestion complete",
      "processed_items": 42,
      "total_items": 42,
      "percentage": 100,
      "discovered_items": 5,
      "created_items": 5,
      "updated_items": 0,
      "reused_items": 0,
      "skipped_items": 0,
      "failed_items": 0,
      "error_summary": null,
      "errors": [],
      "warnings": [],
      "retry_eligible": false,
      "retry_of_job_id": "e4b6c310-850f-48d6-a058-29a502bf65d8",
      "created_at": 1729172500,
      "started_at": 1729172500,
      "completed_at": 1729172502,
      "duration_ms": 2150.0,
      "initiated_by": "admin@vulnify.local"
    }
  }
  ```
- **`400 Bad Request`**: Job is not eligible for retry or status is not `failed`/`partial`.
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Ingestion job not found for project.

---

### 14. `GET /api/projects/{project_id}/services`

Retrieves all distinct services associated with a project, ordered alphabetically by service name. Used to populate the service filter dropdown in the findings list without hardcoding service names.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/services`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**: List of distinct services for the project.
  - **Body**:
    ```json
    [
      {
        "id": "proj-uuid:api-service",
        "name": "api-service"
      },
      {
        "id": "proj-uuid:web-frontend",
        "name": "web-frontend"
      }
    ]
    ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

### 15. `GET /api/projects/{project_id}/findings` (US-201)

Retrieves server-paginated, project-scoped confirmed vulnerability findings grounded in FalkorDB dependency paths and version-matching evidence.

#### Query Parameters
- **`page`** (integer, optional, default: `1`, minimum: `1`): 1-indexed page number.
- **`page_size`** (integer, optional, default: `25`, minimum: `1`, maximum: `100`): Findings per page.
- **`priority`** (string, optional): Filter by Vulnify priority band (`Highest`, `High`, `Medium`, `Low`, `unknown`). Case-insensitive.
- **`service_id`** (string, optional): Filter by associated service identifier.
- **`status`** (string, optional): Filter by triage status (`open`, `under_investigation`, `affected`, `not_affected`, `fixed`). Case-insensitive. Default un-triaged status is `open`.
- **`search`** (string, optional): Case-insensitive text search matching either advisory ID (e.g. `GHSA-29mw-wpgm-hmr9`) or package name (e.g. `lodash`).

#### Semantics & Distinctions
- **Project Scoping**: Only findings associated with services and package versions belonging to the specified project are returned.
- **Deduplication**: When multiple paths connect a service to the same affected package version, the finding is deduplicated to the shortest dependency path.
- **Path Depth**: Distance in hops from the root service to the affected package version. Depth 1 indicates a direct dependency; depth ≥ 2 indicates a transitive dependency.
- **Path Status**:
  - `path_found`: A verified dependency path was found in the graph.
  - `no_path_found`: No dependency path was found from the service to the affected package version. (Does not guarantee safety).
  - `unavailable`: Topology data or dependency analysis was unavailable for the target.
- **Priority**: Vulnify priority band. Unranked findings explicitly return `unknown` rather than fabricating zero risk or exploiting scores.

#### Responses
- **`200 OK`**: Paginated finding results.
  - **Body**:
    ```json
    {
      "items": [
        {
          "id": "find-a1b2c3d4e5f67890",
          "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
          "service_id": "893c5240-a19e-4c55-b8ea-a3d538eec612:payment-api",
          "service_name": "payment-api",
          "advisory_id": "GHSA-29mw-wpgm-hmr9",
          "advisory_summary": "Regular Expression Denial of Service (ReDoS) in lodash",
          "source_url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
          "package_name": "lodash",
          "ecosystem": "npm",
          "package_version": "4.17.20",
          "package_version_id": "npm:lodash@4.17.20",
          "priority": "unknown",
          "status": "open",
          "path_depth": 2,
          "path_status": "path_found",
          "match_reason": "Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-29mw-wpgm-hmr9.",
          "reason_code": "WITHIN_AFFECTED_RANGE",
          "matched_range": "< 4.17.21",
          "fixed_version": "4.17.21",
          "severity": "HIGH",
          "retrieved_at": 1729172000
        }
      ],
      "page": 1,
      "page_size": 25,
      "total": 1,
      "total_pages": 1
    }
    ```
- **`401 Unauthorized`**: Authentication required (`AUTHENTICATION_REQUIRED`).
- **`404 Not Found`**: Project not found (`PROJECT_NOT_FOUND`).
- **`422 Unprocessable Entity`**: Invalid query parameters (e.g. `page < 1` or `page_size > 100`).
- **`500 Internal Server Error`**: FalkorDB connection or query failure (`INTERNAL_SERVER_ERROR`).

---

### 16. `GET /api/projects/{project_id}/findings/summary` (US-202)

Retrieves server-aggregated finding count metrics for summary cards on the Findings page, computed from stored FalkorDB graph relationships.

#### Query Parameters
All query parameters are optional and apply the identical filter scope as the Findings List (`GET /api/projects/{project_id}/findings`), ensuring the summary card metrics always reconcile with the table totals.
- **`priority`** (string, optional): Filter by Vulnify priority band (`Highest`, `High`, `Medium`, `Low`, `unknown`). Case-insensitive.
- **`service_id`** (string, optional): Filter by associated service identifier.
- **`status`** (string, optional): Filter by triage status (`open`, `under_investigation`, `affected`, `not_affected`, `fixed`). Case-insensitive.
- **`search`** (string, optional): Case-insensitive text search matching either advisory ID or package name.

#### Metrics and Semantics
- **`advisory_matches`**: Total number of confirmed vulnerability findings matching the project and active filters (`r.status = 'affected'`). Corresponds exactly to `total` from the findings list.
- **`findings_with_path`**: Number of findings with a confirmed architectural dependency path from a service to the affected package version (`path_status = 'path_found'` / `path_depth >= 1`).
- **`findings_without_path`**: Number of findings where no architectural dependency path could be traced (`path_status = 'no_path_found'` / `path_depth IS NULL`). Reconciles such that `findings_with_path + findings_without_path == advisory_matches`.
- **`findings_needing_decision`**: Number of findings that require a human triage decision (`status IN ['open', 'under_investigation']`). Findings with completed decisions (`affected`, `not_affected`, `fixed`) are excluded.

#### Responses
- **`200 OK`**: Summary metrics for the project.
  - **Body**:
    ```json
    {
      "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
      "advisory_matches": 100,
      "findings_with_path": 65,
      "findings_without_path": 35,
      "findings_needing_decision": 20
    }
    ```
- **`401 Unauthorized`**: Authentication required (`AUTHENTICATION_REQUIRED`).
- **`404 Not Found`**: Project not found (`PROJECT_NOT_FOUND`).
- **`500 Internal Server Error`**: FalkorDB connection or query failure (`INTERNAL_SERVER_ERROR`).

---

### 17. `GET /api/projects/{project_id}/findings/{finding_id}` (US-203)

Retrieves full security evidence, version-matching justification, advisory metadata, and reachability path information for a single finding within a project.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/findings/{finding_id}`
- **Headers**:
  - `X-Requested-With: vulnify`

#### URL Parameters
- **`project_id`** (string, required): Associated project identifier.
- **`finding_id`** (string, required): Deterministic finding ID (e.g., `find-a1b2c3d4e5f67890`) or advisory identifier (e.g., `GHSA-29mw-wpgm-hmr9`).

#### Security & Rendering Note
Advisory text (`advisory_details`, `advisory_summary`) is untrusted input from external vulnerability databases (OSV/NVD). Clients must render this content as **plain text only** with no raw HTML evaluation or injection.

#### Responses
- **`200 OK`**: Complete finding detail with full evidence and justification.
  - **Body**:
    ```json
    {
      "id": "find-a1b2c3d4e5f67890",
      "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
      "service_id": "893c5240-a19e-4c55-b8ea-a3d538eec612:payment-api",
      "service_name": "payment-api",
      "advisory_id": "GHSA-29mw-wpgm-hmr9",
      "advisory_summary": "Regular Expression Denial of Service (ReDoS) in lodash",
      "advisory_details": "All versions of package lodash prior to 4.17.21 are vulnerable to Regular Expression Denial of Service (ReDoS)...",
      "severity": "HIGH",
      "source_url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
      "retrieved_at": 1729172000,
      "aliases": ["CVE-2020-28500"],
      "package_name": "lodash",
      "ecosystem": "npm",
      "package_version": "4.17.20",
      "package_version_id": "npm:lodash@4.17.20",
      "priority": "unknown",
      "status": "open",
      "path_depth": 2,
      "path_status": "path_found",
      "match_reason": "Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-29mw-wpgm-hmr9.",
      "reason_code": "WITHIN_AFFECTED_RANGE",
      "matched_range": "< 4.17.21",
      "fixed_version": "4.17.21"
    }
    ```
- **`401 Unauthorized`**: Authentication required (`AUTHENTICATION_REQUIRED`).
- **`404 Not Found`**: Project or finding not found (`PROJECT_NOT_FOUND` or `Finding '...' not found in project '...'`).
- **`500 Internal Server Error`**: Database query failure (`INTERNAL_SERVER_ERROR`).

---

### 18. `GET /api/projects/{project_id}/findings/{finding_id}/paths` (US-204)

Retrieves bounded, deterministic shortest dependency paths from the root service to an affected package version, including intermediate dependency nodes, edges, provenance metadata, and screen-reader accessible summaries.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/findings/{finding_id}/paths`
- **Headers**:
  - `X-Requested-With: vulnify`

#### URL Parameters
- **`project_id`** (string, required): Associated project identifier.
- **`finding_id`** (string, required): Deterministic finding ID or advisory ID.

#### Query Parameters
- **`max_depth`** (integer, optional, default: `8`, min: `1`, max: `15`): Maximum traversal depth bound.
- **`limit`** (integer, optional, default: `5`, min: `1`, max: `20`): Maximum number of shortest paths to return.

#### Semantics & Distinctions
- **Shortest-First Order**: Direct dependencies (`depth: 1`, `is_direct: true`) appear before transitive dependencies (`depth: 2+`, `is_direct: false`).
- **Provenance on Every Node**: Each node exposes import source filename, content hash, imported_at timestamp, and classification (`manifest`). If provenance is unavailable, explicit `null` values are returned rather than fabricated data.
- **Honesty Guarantee**: If no path is found within search bounds (`has_path: false`, `paths: []`), this indicates absence of an architectural path, not a guarantee of security or exploitability immunity.
- **Cycle & Duplicate Elimination**: Paths with cyclic node repetitions or duplicate node sequences are eliminated in the backend engine.

#### Responses
- **`200 OK`**: Shortest bounded dependency paths.
  - **Body**:
    ```json
    {
      "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
      "finding_id": "find-a1b2c3d4e5f67890",
      "service_id": "893c5240-a19e-4c55-b8ea-a3d538eec612:payment-api",
      "service_name": "payment-api",
      "advisory_id": "GHSA-29mw-wpgm-hmr9",
      "package_name": "lodash",
      "package_version": "4.17.20",
      "package_version_id": "npm:lodash@4.17.20",
      "paths": [
        {
          "id": "path-0123456789abcdef",
          "depth": 2,
          "is_direct": false,
          "nodes": [
            {
              "id": "893c5240-a19e-4c55-b8ea-a3d538eec612:payment-api",
              "node_type": "service",
              "display_name": "payment-api",
              "package_name": null,
              "package_version": null,
              "ecosystem": null,
              "purl": null,
              "is_target": false,
              "is_entry_point": true,
              "provenance": {
                "source_filename": "package-lock.json",
                "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "imported_at": 1729172000,
                "classification": "manifest",
                "origin": "stored_graph"
              }
            },
            {
              "id": "npm:express@4.17.1",
              "node_type": "package",
              "display_name": "express@4.17.1",
              "package_name": "express",
              "package_version": "4.17.1",
              "ecosystem": "npm",
              "purl": "pkg:npm/express@4.17.1",
              "is_target": false,
              "is_entry_point": false,
              "provenance": {
                "source_filename": "package-lock.json",
                "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "imported_at": 1729172000,
                "classification": "manifest",
                "origin": "stored_graph"
              }
            },
            {
              "id": "npm:lodash@4.17.20",
              "node_type": "package",
              "display_name": "lodash@4.17.20",
              "package_name": "lodash",
              "package_version": "4.17.20",
              "ecosystem": "npm",
              "purl": "pkg:npm/lodash@4.17.20",
              "is_target": true,
              "is_entry_point": false,
              "provenance": {
                "source_filename": "package-lock.json",
                "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "imported_at": 1729172000,
                "classification": "manifest",
                "origin": "stored_graph"
              }
            }
          ],
          "edges": [
            {
              "id": "edge-893c5240-a19e-4c55-b8ea-a3d538eec612:payment-api->npm:express@4.17.1",
              "source_id": "893c5240-a19e-4c55-b8ea-a3d538eec612:payment-api",
              "target_id": "npm:express@4.17.1",
              "relationship_type": "DEPENDS_ON",
              "direct": true,
              "origin": "manifest"
            },
            {
              "id": "edge-npm:express@4.17.1->npm:lodash@4.17.20",
              "source_id": "npm:express@4.17.1",
              "target_id": "npm:lodash@4.17.20",
              "relationship_type": "DEPENDS_ON",
              "direct": false,
              "origin": "manifest"
            }
          ],
          "summary_text": "Service: payment-api → express@4.17.1 → lodash@4.17.20"
        }
      ],
      "total_paths_found": 1,
      "max_depth_applied": 8,
      "limit_applied": 5,
      "is_truncated": false,
      "has_path": true,
      "evaluated_at": 1729172000
    }
    ```
- **`401 Unauthorized`**: Authentication required (`AUTHENTICATION_REQUIRED`).
- **`404 Not Found`**: Project or finding not found (`PROJECT_NOT_FOUND` or `Finding '...' not found in project '...'`).
- **`422 Unprocessable Entity`**: Invalid depth or limit query parameter.
- **`500 Internal Server Error`**: Database query failure (`INTERNAL_SERVER_ERROR`).



