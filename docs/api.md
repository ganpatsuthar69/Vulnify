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
- **`sort_by`** (string, optional): Order by `'priority'` for deterministic ranking according to `docs/scoring.md` tie-breakers, or omit for default stable alphanumeric order.

#### Semantics & Distinctions
- **Project Scoping**: Only findings associated with services and package versions belonging to the specified project are returned.
- **Deduplication**: When multiple paths connect a service to the same affected package version, the finding is deduplicated to the shortest dependency path.
- **Path Depth**: Distance in hops from the root service to the affected package version. Depth 1 indicates a direct dependency; depth ≥ 2 indicates a transitive dependency.
- **Path Status**:
  - `path_found`: A verified dependency path was found in the graph.
  - `no_path_found`: No dependency path was found from the service to the affected package version. (Does not guarantee safety).
  - `unavailable`: Topology data or dependency analysis was unavailable for the target.
- **Priority & Reasons (US-301)**: Deterministic priority band (`Highest`, `High`, `Medium`, `Low`, `unknown`) computed by the backend scoring engine according to `docs/scoring.md`. Each finding includes human-readable `priority_reasons` and `scoring_version` (`v1.0.0`). Missing signals explicitly show as `unknown`, never zero risk.

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
          "priority": "High",
          "priority_reasons": [
            "Advisory severity is High",
            "Transitive dependency reachable from service (path depth: 2 hops)",
            "Actionable remediation target available (fixed in >= 4.17.21)"
          ],
          "scoring_version": "v1.0.0",
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
      "priority": "High",
      "priority_reasons": [
        "Advisory severity is High",
        "Transitive dependency reachable from service (path depth: 2 hops)",
        "Actionable remediation target available (fixed in >= 4.17.21)"
      ],
      "scoring_version": "v1.0.0",
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

---

### 19. `GET /api/projects/{project_id}/data-quality` (US-207)

Evaluates project-wide and finding-level data quality warnings, highlighting incomplete analysis scope and enforcing the honesty constraint that absence of evidence does not guarantee safety.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/data-quality`
- **Headers**:
  - `X-Requested-With: vulnify`

#### URL Parameters
- **`project_id`** (string, required): Associated project identifier.

#### Warning Categories & Semantics
1. **`missing_topology`**: Triggers when services exist in the project without recorded inter-service call relationships (`CALLS`). Alerts the user that dependency traversals reflect only internal service dependency graphs and cannot verify architectural reachability from external ingress or across microservices.
2. **`stale_advisory_data`**: Triggers when vulnerability advisories were retrieved more than 7 days ago (604,800 seconds) according to the project's freshness policy, or when retrieval timestamps are missing (`UNKNOWN_ADVISORY_FRESHNESS`).
3. **`partial_import`**: Triggers when recent IngestionJobs terminated with `partial` or `failed` status, or contain skipped/failed package entries.
4. **`no_path`**: Emitted on individual findings or path queries when no architectural dependency path exists within the bounded search depth. Explicitly emphasizes that absence of a path does not guarantee safety or immunity.

#### Responses
- **`200 OK`**: Data quality evaluation results.
  - **Body**:
    ```json
    {
      "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
      "has_warnings": true,
      "warning_count": 2,
      "warnings": [
        {
          "code": "MISSING_TOPOLOGY",
          "category": "missing_topology",
          "severity": "warning",
          "title": "Missing Service Topology",
          "message": "Service-to-service call topology has not been imported. Dependency paths reflect internal service dependencies only and cannot verify architectural exposure from external ingress or across services.",
          "resource_id": null,
          "details": {
            "service_count": 3,
            "call_edge_count": 0
          }
        },
        {
          "code": "STALE_ADVISORY_DATA",
          "category": "stale_advisory_data",
          "severity": "warning",
          "title": "Stale Advisory Data",
          "message": "Advisory data for this project was last refreshed 12 days ago, exceeding the 7-day freshness policy threshold. Newly published vulnerabilities or patched versions may not be reflected.",
          "resource_id": null,
          "details": {
            "threshold_days": 7,
            "last_retrieved_at": 1728134400,
            "age_days": 12
          }
        }
      ],
      "evaluated_at": 1729172000
    }
    ```
- **`401 Unauthorized`**: Authentication required (`AUTHENTICATION_REQUIRED`).
- **`404 Not Found`**: Project not found (`NOT_FOUND`).
- **`500 Internal Server Error`**: Database query failure (`INTERNAL_SERVER_ERROR`).

---

### 20. `GET /api/projects/{project_id}/findings/{finding_id}/upgrade-candidates` (US-401)

Retrieves suggested upgrade targets and compatibility caveats for an individual confirmed finding, derived strictly from advisory fixed versions and server-evaluated SemVer differentials.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/findings/{finding_id}/upgrade-candidates`
- **Headers**:
  - `X-Requested-With: vulnify`

#### URL Parameters
- **`project_id`** (string, required): Associated project identifier.
- **`finding_id`** (string, required): Deterministic finding ID or advisory ID.

#### Core Rules & Acceptance Criteria
1. **Advisory Fixed Version Provenance (AC-1)**: Upgrade candidate versions come strictly from the advisory's verified fixed versions stored in FalkorDB.
2. **Classification & Labelling (AC-1)**: Each candidate is labelled `recommended`, `major version`, or `patch only`. Exactly one lowest-risk target is marked as `is_recommended: true`.
3. **Compatibility Caveats & Honesty (AC-2)**: Shows contextual caveats (breaking change risk, transitive parent package notes, manifest range checks). Vulnify **never claims an upgrade is safe to ship** without project-level testing.
4. **Honest 'No Fix Available' State (AC-3)**: If no fixed version exists in the advisory, `has_fix` is `false`, `candidates` is empty, and an explicit `no_fix_message` and defensive `remediation_guidance` are returned.

#### Responses
- **`200 OK`**: Evaluated upgrade candidates.
  - **Body**:
    ```json
    {
      "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
      "finding_id": "find-a1b2c3d4e5f67890",
      "advisory_id": "GHSA-29mw-wpgm-hmr9",
      "package_name": "lodash",
      "current_version": "4.17.20",
      "ecosystem": "npm",
      "service_id": "893c5240-a19e-4c55-b8ea-a3d538eec612:payment-api",
      "service_name": "payment-api",
      "path_depth": 2,
      "is_transitive": true,
      "has_fix": true,
      "candidates": [
        {
          "target_version": "4.17.21",
          "classification": "recommended",
          "label": "Recommended",
          "labels": ["recommended", "patch only"],
          "semver_diff": "patch",
          "is_recommended": true,
          "fix_status": "fix_supported",
          "compatibility_status": "compatible",
          "breaking_change_risk": "low",
          "caveats": [
            "Patch-only upgrade (v4.17.20 -> v4.17.21): Backwards-compatible bug and security fix. Minimal regression risk within the same release series.",
            "Transitive dependency (depth: 2 hops): Package 'lodash' is brought in by parent dependencies. Direct manifest upgrade may require bumping parent packages or using package manager overrides (e.g. npm 'overrides', yarn 'resolutions', or pip constraints).",
            "Absence of detected conflicts does not guarantee runtime compatibility or application safety. Vulnify never claims an upgrade is safe to ship without project-level integration and regression testing."
          ],
          "evidence_source": "Advisory fixed version declaration"
        }
      ],
      "no_fix_message": null,
      "remediation_guidance": "Review candidate SemVer diffs, check for breaking API changes, and test before applying. Never deploy upgrades directly to production without running test suites.",
      "safety_disclaimer": "No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.",
      "evaluated_at": 1729172000
    }
    ```
- **`401 Unauthorized`**: Authentication required (`AUTHENTICATION_REQUIRED`).
- **`404 Not Found`**: Project or finding not found (`NOT_FOUND`).
- **`500 Internal Server Error`**: Database query failure (`INTERNAL_SERVER_ERROR`).

---

### 21. `GET /api/projects/{project_id}/upgrade-candidates` (US-401 / US-501)

Retrieves project-wide upgrade candidate evaluations for all confirmed findings, providing aggregated remediation metrics and per-finding upgrade recommendations.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/upgrade-candidates`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**: Project-wide upgrade candidate evaluations.
  - **Body**:
    ```json
    {
      "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
      "total_findings": 15,
      "findings_with_fix": 12,
      "findings_without_fix": 3,
      "items": [
        {
          "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
          "finding_id": "find-a1b2c3d4e5f67890",
          "advisory_id": "GHSA-29mw-wpgm-hmr9",
          "package_name": "lodash",
          "current_version": "4.17.20",
          "ecosystem": "npm",
          "service_id": "893c5240-a19e-4c55-b8ea-a3d538eec612:payment-api",
          "service_name": "payment-api",
          "path_depth": 2,
          "is_transitive": true,
          "has_fix": true,
          "candidates": [
            {
              "target_version": "4.17.21",
              "classification": "recommended",
              "label": "Recommended",
              "labels": ["recommended", "patch only"],
              "semver_diff": "patch",
              "is_recommended": true,
              "fix_status": "fix_supported",
              "compatibility_status": "compatible",
              "breaking_change_risk": "low",
              "caveats": [
                "Patch-only upgrade (v4.17.20 -> v4.17.21): Backwards-compatible bug and security fix. Minimal regression risk within the same release series.",
                "Transitive dependency (depth: 2 hops): Package 'lodash' is brought in by parent dependencies. Direct manifest upgrade may require bumping parent packages or using package manager overrides.",
                "Absence of detected conflicts does not guarantee runtime compatibility or application safety. Vulnify never claims an upgrade is safe to ship without project-level integration and regression testing."
              ],
              "evidence_source": "Advisory fixed version declaration"
            }
          ],
          "no_fix_message": null,
          "remediation_guidance": "Review candidate SemVer diffs, check for breaking API changes, and test before applying.",
          "safety_disclaimer": "No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.",
          "evaluated_at": 1729172000
        }
      ],
      "safety_disclaimer": "No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.",
      "evaluated_at": 1729172000
    }
    ```
- **`401 Unauthorized`**: Authentication required (`AUTHENTICATION_REQUIRED`).
- **`404 Not Found`**: Project not found (`NOT_FOUND`).
- **`500 Internal Server Error`**: Database query failure (`INTERNAL_SERVER_ERROR`).

---

### 22. `POST /api/projects/{project_id}/simulations` (US-501 / US-502)

Executes a dry-run fix simulation on an ephemeral in-memory graph overlay without mutating the real FalkorDB graph. Computes the delta of cleared findings, unchanged findings, newly introduced vulnerabilities, severed exposure paths, and SemVer breaking change risk.

#### Request
- **Method**: `POST`
- **Path**: `/api/projects/{project_id}/simulations`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Body**:
  ```json
  {
    "finding_id": "find-a1b2c3d4e5f67890",
    "package_name": "express",
    "current_version": "4.17.1",
    "target_version": "4.18.2",
    "ecosystem": "npm",
    "service_id": null
  }
  ```

#### Responses
- **`200 OK`**: Complete simulation response with findings delta and verification checklist.
  - **Body**:
    ```json
    {
      "id": "sim-e90f238a",
      "project_id": "893c5240-a19e-4c55-b8ea-a3d538eec612",
      "package_name": "express",
      "current_version": "4.17.1",
      "target_version": "4.18.2",
      "ecosystem": "npm",
      "service_id": "893c5240-a19e-4c55-b8ea-a3d538eec612:web-svc",
      "service_name": "web-svc",
      "method": "simulated_from_metadata",
      "method_description": "Evaluated on an in-memory graph overlay using OSV advisory version metadata and lockfile dependency paths without mutating stored graph data.",
      "is_simulation": true,
      "real_graph_mutated": false,
      "baseline_id": "snap-a8c9e120f",
      "is_transitive": false,
      "path_depth": 1,
      "paths_severed_count": 1,
      "paths_remaining_count": 0,
      "dependent_services": ["web-svc"],
      "cleared_findings": [
        {
          "finding_id": "find-a1b2c3d4e5f67890",
          "advisory_id": "GHSA-1234-abcd",
          "package_name": "express",
          "installed_version": "4.17.1",
          "target_version": "4.18.2",
          "severity": "HIGH",
          "status": "expected_resolved",
          "explanation": "Proposed version 4.18.2 is at or above verified fixed version 4.17.3 for advisory GHSA-1234-abcd.",
          "source_url": "https://github.com/advisories/GHSA-1234-abcd"
        }
      ],
      "unchanged_findings": [],
      "newly_introduced_findings": [],
      "total_findings_cleared": 1,
      "total_findings_unchanged": 0,
      "total_findings_introduced": 0,
      "compatibility_status": "compatible",
      "breaking_change_risk": "low",
      "resolver_status": "not_evaluated",
      "compatibility_caveats": [
        "Minor/patch version upgrade: backward-compatible according to SemVer convention, but regression testing is always required.",
        "Absence of detected conflicts does not guarantee runtime compatibility or application safety. Vulnify never claims an upgrade is safe to ship without project-level integration and regression testing."
      ],
      "checks_performed": [
        {
          "name": "Advisory Fixed Version Verification",
          "status": "passed",
          "description": "Evaluated 1 baseline finding(s) for express against target version 4.18.2. 1 expected to clear."
        },
        {
          "name": "Graph Path Exposure Analysis",
          "status": "passed",
          "description": "Simulated severing of 1 vulnerable reachability path(s) on graph overlay."
        },
        {
          "name": "SemVer Compatibility & Breaking Risk",
          "status": "passed",
          "description": "SemVer differential assessed as 'minor' jump with 'low' breaking change risk."
        },
        {
          "name": "Package Manager Lockfile Resolution",
          "status": "not_evaluated",
          "description": "Graph simulation only; real package-manager resolution (npm/pip) was not executed."
        },
        {
          "name": "Runtime Sandbox Execution",
          "status": "not_evaluated",
          "description": "Non-mutating metadata simulation; dynamic container execution not performed."
        }
      ],
      "safety_disclaimer": "No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.",
      "created_at": 1729173000
    }
    ```
- **`401 Unauthorized`**: Authentication required (`AUTHENTICATION_REQUIRED`).
- **`404 Not Found`**: Project or finding not found (`NOT_FOUND`).
- **`422 Unprocessable Entity`**: Invalid package/version inputs (`VALIDATION_ERROR`).
- **`500 Internal Server Error`**: Simulation failure (`INTERNAL_SERVER_ERROR`).

---

### 23. `GET /api/projects/{project_id}/simulations` (US-501 / US-502)

Retrieves recent fix simulations performed for the specified project.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/simulations`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**: List of recent simulation responses.
  - **Body**:
    ```json
    {
      "items": [ /* SimulationResponse objects */ ],
      "total": 1
    }
    ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

### 24. `GET /api/projects/{project_id}/simulations/{simulation_id}` (US-501 / US-502)

Retrieves full details and verification checklist for a specific simulation run.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/simulations/{simulation_id}`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**: Specific `SimulationResponse` object.
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Simulation run not found.

---

## GitHub Remediation Issue Endpoints (US-503 / US-504 / US-505)

### 25. `GET /api/projects/{project_id}/github/status` (US-503 / US-504)

Retrieves server-side GitHub integration status and default target repository without leaking credentials or API tokens.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/github/status`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**:
  ```json
  {
    "configured": true,
    "default_owner": "vulnify",
    "default_repo": "demo-workspace",
    "target_repo": "vulnify/demo-workspace",
    "api_base_url": "https://api.github.com"
  }
  ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

### 26. `POST /api/projects/{project_id}/findings/{finding_id}/github-issues/preview` (US-503)

Generates a structured, evidence-backed GitHub issue preview with a deterministic SHA-256 plan hash. Raw unquoted advisory text is never used, and angle brackets are sanitized to prevent raw HTML execution. Editing the title changes the plan hash and resets any prior approval state.

#### Request
- **Method**: `POST`
- **Path**: `/api/projects/{project_id}/findings/{finding_id}/github-issues/preview`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Body**:
  ```json
  {
    "title_override": "[Security] Remediate lodash@4.17.20 (GHSA-29mw-wpgm-hmr9)",
    "target_version": "4.17.21",
    "target_repo": "vulnify/demo-workspace"
  }
  ```

#### Responses
- **`200 OK`**:
  ```json
  {
    "project_id": "proj-1",
    "finding_id": "find-1",
    "advisory_id": "GHSA-29mw-wpgm-hmr9",
    "package_name": "lodash",
    "current_version": "4.17.20",
    "target_version": "4.17.21",
    "ecosystem": "npm",
    "service_name": "payment-api",
    "target_repo": "vulnify/demo-workspace",
    "title": "[Security] Remediate lodash@4.17.20 (GHSA-29mw-wpgm-hmr9)",
    "body": "## Vulnerability Remediation Request\n\n### Target Package\n...",
    "plan_hash": "plan_sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "can_submit": true,
    "configuration_warning": null,
    "generated_at": 1729173000
  }
  ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project or finding not found.

---

### 27. `POST /api/projects/{project_id}/findings/{finding_id}/github-issues` (US-504)

Creates a real GitHub issue via GitHub REST API after explicit human approval (`confirmed: true`) and plan hash verification. Re-submitting the same plan hash returns the existing issue without creating duplicates. Requires CSRF protection header `X-Requested-With: vulnify`.

#### Request
- **Method**: `POST`
- **Path**: `/api/projects/{project_id}/findings/{finding_id}/github-issues`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Body**:
  ```json
  {
    "plan_hash": "plan_sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "title": "[Security] Remediate lodash@4.17.20 (GHSA-29mw-wpgm-hmr9)",
    "body": "## Vulnerability Remediation Request\n...",
    "target_repo": "vulnify/demo-workspace",
    "target_version": "4.17.21",
    "confirmed": true
  }
  ```

#### Responses
- **`200 OK`**:
  ```json
  {
    "id": "gh-issue-abc12345",
    "project_id": "proj-1",
    "finding_id": "find-1",
    "target_repo": "vulnify/demo-workspace",
    "issue_number": 42,
    "issue_url": "https://github.com/vulnify/demo-workspace/issues/42",
    "title": "[Security] Remediate lodash@4.17.20 (GHSA-29mw-wpgm-hmr9)",
    "plan_hash": "plan_sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "created_by": "admin@vulnify.local",
    "state": "open",
    "created_at": 1729173000,
    "is_duplicate": false,
    "message": "GitHub issue #42 created successfully in vulnify/demo-workspace."
  }
  ```
- **`400 Bad Request`**: Missing `confirmed: true`, tampered plan hash, or missing `GITHUB_TOKEN`.
- **`403 Forbidden`**: Token lacks issue write permissions on repository.
- **`404 Not Found`**: Target repository or finding not found on GitHub.
- **`422 Unprocessable Content`**: Invalid repository format or rejected payload.
- **`429 Too Many Requests`**: GitHub API rate limit exceeded.

---

### 28. `GET /api/projects/{project_id}/github-issues` (US-505 / US-506)

Lists all GitHub issues created for findings in the specified project.

#### Request
- **Method**: `GET`
- **Path**: `/api/projects/{project_id}/github-issues`
- **Headers**:
  - `X-Requested-With: vulnify`

#### Responses
- **`200 OK`**:
  ```json
  {
    "items": [
      {
        "id": "gh-issue-abc12345",
        "project_id": "proj-1",
        "finding_id": "find-1",
        "target_repo": "vulnify/demo-workspace",
        "issue_number": 42,
        "issue_url": "https://github.com/vulnify/demo-workspace/issues/42",
        "title": "[Security] Remediate lodash@4.17.20 (GHSA-29mw-wpgm-hmr9)",
        "plan_hash": "plan_sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "created_by": "admin@vulnify.local",
        "state": "open",
        "created_at": 1729173000,
        "is_duplicate": false,
        "message": "GitHub issue #42 created successfully in vulnify/demo-workspace."
      }
    ],
    "total": 1
  }
  ```
- **`401 Unauthorized`**: Authentication required.
- **`404 Not Found`**: Project not found.

---

### 27. Agent Tools & MCP Registry Endpoints (US-601)

#### `GET /api/agent/tools`
- **Description**: Returns all dynamically registered agent tools, their schemas, classifications, and approval requirements.
- **Authentication**: Required (`require_auth`).
- **Response**: `200 OK`
  ```json
  {
    "tools": [
      {
        "name": "list_findings",
        "description": "Retrieve vulnerability findings for a project with bounded filtering and pagination.",
        "classification": "read_only",
        "query_id": "get_project_findings",
        "requires_approval": false,
        "input_schema": {
          "properties": {
            "project_id": {"title": "Project Id", "type": "string"},
            "page": {"default": 1, "minimum": 1, "title": "Page", "type": "integer"},
            "page_size": {"default": 25, "maximum": 100, "minimum": 1, "title": "Page Size", "type": "integer"}
          },
          "required": ["project_id"],
          "type": "object"
        }
      }
    ],
    "total": 7
  }
  ```

#### `GET /api/agent/tools/{tool_name}`
- **Description**: Retrieve specification and parameter schema for a single agent tool.
- **Authentication**: Required (`require_auth`).
- **Response**: `200 OK` (ToolMetadata) or `404 Not Found`.

#### `POST /api/agent/tools/{tool_name}/execute`
- **Description**: Execute a registered agent tool. Enforces input schema validation, approval gating on write tools (`confirmed: true`), execution timing, and structured trace generation.
- **Authentication**: Required (`require_auth`).
- **CSRF**: Enforced (`X-Requested-With: vulnify`).
- **Request Body**: JSON dictionary of tool parameters.
- **Response**: `200 OK`
  ```json
  {
    "tool_name": "list_findings",
    "status": "success",
    "data": {
      "items": [],
      "total": 0,
      "page": 1,
      "page_size": 25
    },
    "trace": {
      "tool_name": "list_findings",
      "tool_version": "1.0.0",
      "query_id": "get_project_findings",
      "inputs": {"project_id": "proj-1"},
      "result_summary": "No findings found for project 'proj-1' matching criteria.",
      "duration_ms": 1.45,
      "record_count": 0,
      "evaluated_at": 1729267200,
      "outcome": "empty",
      "evidence_references": [],
      "warning": null
    },
    "error_message": null
  }
  ```
- **Rejection Example (Write Tool without Confirmation)**:
  ```json
  {
    "tool_name": "record_decision",
    "status": "rejected",
    "data": null,
    "trace": {
      "tool_name": "record_decision",
      "query_id": "record_triage_decision",
      "result_summary": "Execution rejected for 'record_decision': explicit human approval is required ('confirmed': true).",
      "outcome": "rejected",
      "warning": "Gated write tool blocked without human confirmation."
    },
    "error_message": "Tool 'record_decision' is a write-capable tool and requires explicit human approval ('confirmed': true)."
  }
  ```

---

### 29. Agent Interactive Chat & Streaming Endpoints (US-602)

#### `POST /api/agent/chat/stream`
- **Description**: Stream agent investigation events, intermediate tool dispatches, and evidence-grounded answer tokens using Server-Sent Events (SSE).
- **Authentication**: Required (`require_auth`). Admin only (`role == "admin"`).
- **CSRF**: Enforced (`X-Requested-With: vulnify`).
- **Request Body**:
  ```json
  {
    "project_id": "proj-1",
    "message": "Explain how payment-service reaches lodash and rank findings",
    "run_id": "run-optional-id"
  }
  ```
- **Response Headers**:
  - `Content-Type: text/event-stream`
  - `Cache-Control: no-cache`
  - `Connection: keep-alive`
- **SSE Event Format**:
  Each event follows standard SSE formatting:
  ```text
  event: <event_name>
  data: {"event": "<event_name>", "run_id": "...", "sequence": 1, "timestamp": 1729267200, "data": {...}}

  ```
- **Event Types**:
  - `run_started`: Emitted upon run initialization with `step_limit` and `timeout_seconds`.
  - `assistant_status`: Status message indicating internal reasoning state.
  - `tool_started`: Emitted before tool execution with tool inputs and call ID.
  - `tool_completed`: Emitted after tool execution with execution duration, outcome, and trace fragment.
  - `answer_delta`: Incremental stream of answer text tokens.
  - `answer_completed`: Final synthesised response text with references to findings and dependency paths.
  - `run_cancelled`: Emitted if the run was halted by user request or client disconnect.
  - `run_timeout`: Emitted if wall-clock timeout (`AGENT_RUN_TIMEOUT_SECONDS`) was exceeded.
  - `run_step_limit`: Emitted if maximum step budget (`AGENT_STEP_LIMIT`) was reached.
  - `run_completed`: Final terminal event with total steps and elapsed duration.
  - `run_failed`: Emitted if an unhandled internal exception occurred.
- **Status Codes**:
  - `200 OK`: Stream opened successfully.
  - `401 Unauthorized`: Authentication missing.
  - `403 Forbidden`: Authenticated user is not an administrator (`role != "admin"`), or CSRF header missing.
  - `404 Not Found`: Target project does not exist.
  - `422 Unprocessable Content`: Empty message or exceeds 2,000 characters.

#### `POST /api/agent/runs/{run_id}/cancel`
- **Description**: Signals cancellation to an in-flight agent run. The orchestrator will stop dispatching subsequent tool steps and gracefully conclude the stream.
- **Authentication**: Required (`require_auth`). Admin only (`role == "admin"`).
- **CSRF**: Enforced (`X-Requested-With: vulnify`).
- **Response**: `200 OK`
  ```json
  {
    "run_id": "run-abc12345",
    "status": "cancelled",
    "message": "Run 'run-abc12345' cancellation signal recorded."
  }
  ```
- **Status Codes**:
  - `200 OK`: Cancellation processed (status may be `cancelled`, `already_terminal`, or `not_found`).
  - `401 Unauthorized`: Authentication required.
  - `403 Forbidden`: Admin role required.

#### `GET /api/agent/runs/{run_id}/status`
- **Description**: Inspect execution status, step count, and timestamps for an agent run.
- **Authentication**: Required (`require_auth`). User or Admin.
- **Response**: `200 OK`
  ```json
  {
    "run_id": "run-abc12345",
    "project_id": "proj-1",
    "status": "completed",
    "step_count": 3,
    "created_at": 1729267200,
    "completed_at": 1729267205,
    "error_message": null
  }
  ```

---

### 30. Agent Stored Traces & Investigation History Endpoints (US-603)

#### `GET /api/agent/runs`
- **Description**: Paginated listing of past agent runs for a project.
- **Authentication**: Required (`require_auth`). Admin only (`role == "admin"`).
- **Query Parameters**:
  - `project_id` (string, required): Project identifier to filter runs.
  - `page` (integer, optional, default: 1): Page number (1-based).
  - `page_size` (integer, optional, default: 25, max: 100): Number of records per page.
- **Response**: `200 OK`
  ```json
  {
    "items": [
      {
        "id": "run-abc12345",
        "project_id": "proj-1",
        "user_email": "admin@vulnify.local",
        "prompt": "Explain how payment-service reaches lodash",
        "status": "completed",
        "started_at": 1729267200,
        "completed_at": 1729267205,
        "has_final_answer": true,
        "step_count": 3,
        "tool_call_count": 3,
        "error_message": null
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 25
  }
  ```
- **Status Codes**:
  - `200 OK`: Runs retrieved.
  - `401 Unauthorized`: Authentication missing.
  - `403 Forbidden`: Admin role required.
  - `404 Not Found`: Project not found.

#### `GET /api/agent/runs/{run_id}`
- **Description**: Retrieve detailed metadata and generated answer for a single agent investigation session.
- **Authentication**: Required (`require_auth`). Admin only (`role == "admin"`).
- **Response**: `200 OK`
  ```json
  {
    "id": "run-abc12345",
    "project_id": "proj-1",
    "user_id": "admin-uuid",
    "user_email": "admin@vulnify.local",
    "prompt": "Explain how payment-service reaches lodash",
    "status": "completed",
    "started_at": 1729267200,
    "completed_at": 1729267205,
    "final_answer": "Analysis concluded: lodash is reached transitively via async@3.2.0.",
    "error_message": null,
    "step_count": 3,
    "findings_referenced": ["find-lodash-1"],
    "paths_referenced": ["Service: payment-svc -> async@3.2.0 -> lodash@4.17.20"],
    "tool_call_count": 3
  }
  ```
- **Status Codes**:
  - `200 OK`: Run found and returned.
  - `401 Unauthorized`: Authentication required.
  - `403 Forbidden`: Admin role required.
  - `404 Not Found`: Run not found.

#### `GET /api/agent/runs/{run_id}/trace`
- **Description**: Retrieve the complete audit trace containing all ordered tool executions, sanitized inputs, result summaries, query IDs, and latency telemetry.
- **Authentication**: Required (`require_auth`). Admin only (`role == "admin"`).
- **Response**: `200 OK`
  ```json
  {
    "run": {
      "id": "run-abc12345",
      "project_id": "proj-1",
      "user_id": "admin-uuid",
      "user_email": "admin@vulnify.local",
      "prompt": "Explain how payment-service reaches lodash",
      "status": "completed",
      "started_at": 1729267200,
      "completed_at": 1729267205,
      "final_answer": "...",
      "error_message": null,
      "step_count": 2,
      "findings_referenced": ["find-lodash-1"],
      "paths_referenced": ["..."],
      "tool_call_count": 2
    },
    "tool_calls": [
      {
        "id": "call-1",
        "run_id": "run-abc12345",
        "sequence": 1,
        "tool_name": "list_findings",
        "display_name": "Querying project findings list",
        "inputs": {"project_id": "proj-1", "page": 1, "page_size": 25},
        "result_summary": "Retrieved 1 open finding(s).",
        "status": "success",
        "query_id": "get_project_findings",
        "duration_ms": 3.42,
        "outcome": "success",
        "evidence_references": ["find-lodash-1"],
        "started_at": 1729267201,
        "completed_at": 1729267202,
        "error_message": null
      },
      {
        "id": "call-2",
        "run_id": "run-abc12345",
        "sequence": 2,
        "tool_name": "get_dependency_paths",
        "display_name": "Traversing graph paths to lodash@4.17.20",
        "inputs": {"project_id": "proj-1", "finding_id": "find-lodash-1"},
        "result_summary": "Discovered 1 dependency path(s).",
        "status": "success",
        "query_id": "get_project_finding_paths",
        "duration_ms": 8.15,
        "outcome": "success",
        "evidence_references": ["find-lodash-1"],
        "started_at": 1729267202,
        "completed_at": 1729267203,
        "error_message": null
      }
    ]
  }
  ```
- **Status Codes**:
  - `200 OK`: Trace retrieved.
  - `401 Unauthorized`: Authentication required.
  - `403 Forbidden`: Admin role required.
  - `404 Not Found`: Run not found.

#### `GET /api/agent/runs/by-finding/{finding_id}`
- **Description**: Retrieve past agent investigation sessions that referenced or evaluated a specific finding ID.
- **Authentication**: Required (`require_auth`). Admin only (`role == "admin"`).
- **Query Parameters**:
  - `project_id` (string, required): Project identifier context.
  - `limit` (integer, optional, default: 10, max: 50): Max runs to return.
- **Response**: `200 OK`
  ```json
  [
    {
      "id": "run-abc12345",
      "project_id": "proj-1",
      "user_email": "admin@vulnify.local",
      "prompt": "Deep dive on lodash exposure",
      "status": "completed",
      "started_at": 1729267200,
      "completed_at": 1729267205,
      "has_final_answer": true,
      "step_count": 2,
      "tool_call_count": 2,
      "error_message": null
    }
  ]
  ```
- **Status Codes**:
  - `200 OK`: Matching runs list (empty list if no investigations reference the finding).
  - `401 Unauthorized`: Authentication required.
  - `403 Forbidden`: Admin role required.
  - `404 Not Found`: Project not found.

---

## Benchmark Question Set Endpoints (US-801)

### 31. `GET /api/benchmarks/cases`
- **Description**: List hand-verified benchmark cases with optional category and difficulty filtering.
- **Authentication**: None (public benchmark access for validation and evaluation harness).
- **Query Parameters**:
  - `category` (string, optional): One of `path_exists`, `no_path`, `exposure`, `ranking`, `remediation`.
  - `difficulty` (string, optional): One of `easy`, `medium`, `hard`.
- **Response**: `200 OK`
  ```json
  {
    "cases": [
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
          "explanation": "Graph traversal reveals that authentication-service directly imports jsonwebtoken@8.5.1 as declared in its package manifest. Shortest hop distance is 1.",
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
    ],
    "total": 20,
    "category_filter": null,
    "difficulty_filter": null
  }
  ```
- **Status Codes**:
  - `200 OK`: Successful retrieval.

### 32. `GET /api/benchmarks/cases/{case_id}`
- **Description**: Retrieve detailed specification, expected answer, and review records for a single benchmark case.
- **Authentication**: None.
- **Path Parameters**:
  - `case_id` (string, required): Benchmark case ID (e.g. `BM-001`).
- **Response**: `200 OK` (single `BenchmarkCase` object).
- **Status Codes**:
  - `200 OK`: Case found.
  - `404 Not Found`: Case not found.

### 33. `GET /api/benchmarks/summary`
- **Description**: Retrieve overview metrics of benchmark category coverage, difficulty distributions, and two-person review status.
- **Authentication**: None.
- **Response**: `200 OK`
  ```json
  {
    "dataset_version": "1.0.0",
    "dataset_title": "Vulnify Security Investigation Benchmark",
    "coverage": {
      "total_cases": 20,
      "by_category": {
        "path_exists": 4,
        "no_path": 4,
        "exposure": 4,
        "ranking": 4,
        "remediation": 4
      },
      "by_difficulty": {
        "easy": 7,
        "medium": 8,
        "hard": 5
      },
      "verified_count": 20,
      "pending_verification_count": 0,
      "blocked_verification_count": 0
    },
    "reviews": {
      "total_cases": 20,
      "fully_approved_count": 20,
      "pending_first_review_count": 0,
      "pending_second_review_count": 0,
      "changes_requested_count": 0,
      "blocked_count": 0,
      "reviewer_counts": {
        "reviewer-sec-graph-lead": 20,
        "reviewer-appsec-lead": 20
      }
    }
  }
  ```
- **Status Codes**:
  - `200 OK`: Successful retrieval.

---

### 34. `GET /api/benchmarks/results/latest`
- **Description**: Retrieve the most recent benchmark comparison run result between Vulnify Graph Agent and RAG Baseline. Returns `404 Not Found` if no benchmark run has been completed yet (supporting the US-803 "no results yet" empty state).
- **Authentication**: None.
- **Response**: `200 OK` (returns `BenchmarkRunResult` conforming to `benchmarks/results_schema.json`)
  ```json
  {
    "run_id": "run-20261018-090000",
    "dataset_version": "1.0.0",
    "started_at": "2026-10-18T09:00:00Z",
    "completed_at": "2026-10-18T09:01:15Z",
    "protocol": {
      "llm_provider": "openai",
      "llm_model": "gpt-4o-mini",
      "temperature": 0.0,
      "graph_system": "Vulnify Graph Agent",
      "rag_system": "Lexical BM25 Baseline",
      "corpus_doc_count": 25,
      "rag_top_k": 3
    },
    "summary": {
      "total_cases": 20,
      "graph_success_count": 20,
      "rag_success_count": 18,
      "graph_avg_duration_ms": 245.5,
      "rag_avg_duration_ms": 112.3
    },
    "cases": []
  }
  ```
- **Status Codes**:
  - `200 OK`: Latest run found and returned.
  - `404 Not Found`: No benchmark runs exist yet (`latest_run.json` not found). The client renders the empty state.
  - `500 Internal Server Error`: Failed to parse results artifact.

---

### 35. `GET /api/benchmarks/results`
- **Description**: List all historical benchmark comparison run artifacts with high-level metadata (run ID, timestamps, total cases, success counts).
- **Authentication**: None.
- **Response**: `200 OK`
  ```json
  [
    {
      "filename": "benchmark_run_20261018_112640.json",
      "run_id": "run-20261018-112640",
      "created_at": "2026-10-18T11:26:40Z",
      "dataset_version": "1.0.0",
      "total_cases": 20,
      "graph_success_count": 20,
      "rag_success_count": 20
    }
  ]
  ```
- **Status Codes**:
  - `200 OK`: Successful retrieval.

---

### 36. `GET /api/benchmarks/results/run/{filename}`
- **Description**: Retrieve a specific historical benchmark comparison run result by its sanitized filename.
- **Authentication**: None.
- **Path Parameters**:
  - `filename` (string, required): Clean artifact filename (e.g. `benchmark_run_20261018_112640.json`).
- **Response**: `200 OK` (returns full `BenchmarkRunResult`).
- **Status Codes**:
  - `200 OK`: Specified run artifact found.
  - `400 Bad Request`: Malformed or directory-traversal filename.
  - `404 Not Found`: File not found in `benchmarks/results/`.
  - `500 Internal Server Error`: Parsing failure.

---

### 37. `POST /api/benchmarks/run`
- **Description**: Trigger a reproducible, single-command comparison execution between Vulnify Graph Agent and RAG Baseline under identical models and evidence corpora.
- **Authentication**: None.
- **Request Body**:
  ```json
  {
    "category": "path_exists",
    "dry_run": false,
    "llm_provider": "mistral",
    "llm_model": "mistral-small-latest",
    "temperature": 0.0
  }
  ```
  - `category` (string, optional): Restrict execution to a single category (`path_exists`, `no_path`, `exposure`, `ranking`, `remediation`). If omitted, runs all categories.
  - `dry_run` (boolean, optional): If `true`, runs harness verification without live LLM calls. Default `false`.
  - `llm_provider` (string, optional): LLM provider (`mistral`, `auto`, `openai`, `gemini`, `deterministic_test`). Default `"mistral"`.
  - `llm_model` (string, optional): Model identifier. Default `"mistral-small-latest"`.
  - `temperature` (number, optional): Generation temperature. Default `0.0`.
- **Response**: `200 OK` (returns completed `BenchmarkRunResult`).
- **Status Codes**:
  - `200 OK`: Comparison run completed successfully.
  - `500 Internal Server Error`: Execution failed.

