# Vulnify — Technology Stack & Ecosystem Analysis

> **Definitive Inventory of Frameworks, Libraries, Runtimes, and Architecture Choices**  
> *A comprehensive technical review of all verified dependencies and their architectural justification.*

---

## 1. Stack Summary

| Domain | Technology | Verified Version | Role in Vulnify |
| :--- | :--- | :--- | :--- |
| **Backend Runtime** | Python | `>= 3.12` | Core application runtime, async event loop, parsers |
| **Web Framework** | FastAPI | `>= 0.115.0` | High-performance ASGI REST & SSE streaming server |
| **Server Engine** | Uvicorn (standard) | `>= 0.32.0` | Production ASGI HTTP/1.1 & WebSocket/SSE server |
| **Validation & Settings** | Pydantic / Pydantic-Settings | `>= 2.10.0` / `>= 2.6.0` | Data models, request/response validation, env config |
| **Graph Database** | FalkorDB | `latest` (Docker) | Primary low-latency graph database (RedisGraph engine) |
| **Graph Client** | FalkorDB-Py / Redis | `>= 1.0.10` / `>= 5.2.0` | Asynchronous & synchronous FalkorDB Cypher drivers |
| **Agent / MCP Protocol** | FastMCP / MCP SDK | `>= 2.3.0` | Model Context Protocol tool schemas and execution |
| **Authentication & Crypto**| Argon2id / PyJWT | `>= 23.1.0` / `>= 2.8.0` | Password hashing, session token creation & verification |
| **HTTP Client** | HTTPX | `>= 0.28.0` | Async HTTP client for OSV and GitHub REST APIs |
| **Semver & Versions** | packaging / semver | `>= 24.0` / `>= 3.0.0` | PEP 440 and Semantic Versioning range evaluators |
| **Frontend Framework** | React | `19.0.0` | Reactive component UI with Concurrent Mode support |
| **Language & Bundler** | TypeScript / Vite | `5.9.0` / `8.3.0` | Strict type safety, instant HMR, optimized bundling |
| **Routing** | React Router | `8.4.0` | Declarative client-side routing & navigation state |
| **Graph Visualization** | `@xyflow/react` (React Flow) | `12.12.0` | Interactive canvas, custom nodes, zoom/pan navigation |
| **Styling & Icons** | Tailwind CSS / Lucide React | `4.0.0` / `1.16.0` | Modern utility CSS engine & accessible SVG iconography |
| **Testing & Quality** | Pytest / Vitest / axe-core | `8.0.0` / `3.0.0` / `4.10.0` | Backend async testing, frontend unit tests & a11y audits |

---

## 2. Backend Stack Details (`backend/`)

### 2.1 Python 3.12+ Runtime
- **Rationale**: Vulnify leverages modern Python 3.12 features including enhanced typing syntax (`str | None`, generic type aliases), high-performance `asyncio` loop improvements, and native performance gains.
- **Environment**: Isolated strictly within `backend/.venv` to prevent global contamination.

### 2.2 FastAPI & Starlette
- **FastAPI 0.115+**: Chosen for native asynchronous (`async`/`await`) request handling, automatic OpenAPI/Swagger documentation generation, and seamless integration with Pydantic v2.
- **Starlette Middleware**:
  - `CSRFMiddleware`: Custom middleware enforcing `X-Requested-With: vulnify` and checking `Origin` whitelist on mutating HTTP methods.
  - `RequestIdMiddleware`: Generates and propagates `X-Request-ID` across all logs and response headers.
  - `CORSMiddleware`: Explicit origin whitelisting with credentials support.

### 2.3 Pydantic v2 & Pydantic-Settings
- **Pydantic 2.10+**: Powered by the Rust-based `pydantic-core` engine for ultra-fast JSON serialization/deserialization.
- **Pydantic-Settings 2.6+**: Implements centralized, fail-fast configuration parsing from environment variables and `.env` files. Ensures the server refuses to boot if secrets (e.g. `SESSION_SECRET`) are missing or under 32 characters.

### 2.4 FalkorDB & Redis Driver
- **FalkorDB**: Low-latency graph database operating over the Redis wire protocol.
  - *Why FalkorDB over Neo4j?* FalkorDB provides near-instant in-memory graph operations backed by sparse matrix multiplication (GraphBLAS), minimal memory overhead, zero JVM dependencies, and native Docker containerization.
  - *Cypher Support*: Implements openCypher query syntax with bounded traversals, variable-length path matching, and rich property expressions.
- **falkordb-py & redis-py**: Official client libraries handling connection pooling, socket timeouts, and binary protocol framing.

### 2.5 Security, Authentication & Cryptography
- **Argon2id (`argon2-cffi`)**: The gold-standard password hashing algorithm (winner of the Password Hashing Competition), offering superior protection against both GPU and ASIC cracking attacks.
- **PyJWT**: Secure creation and validation of cryptographic session tokens stored in `httpOnly` cookies.
- **Standard Library `hashlib`**: Computes SHA-256 hashes for lockfile content deduplication and remediation plan preview hash verification.

### 2.6 Version Matching & Parsing
- **`semver` (3.0+)**: Evaluates semantic versioning ranges for npm and Cargo ecosystems, including prereleases, build metadata, and tilde/caret (`^`, `~`) specifiers.
- **`packaging` (24.0+)**: Official PyPA specification parser evaluating PEP 440 version ranges (`>=`, `==`, `~=`, `<`) for Python dependencies.
- **Multi-Ecosystem Parsers**: Custom AST and JSON parsers for `package-lock.json` (v1/v2/v3), `Cargo.lock`, `go.mod`, `go.sum`, and `requirements.txt`.

### 2.7 FastMCP & AI Agent Orchestration
- **`mcp` (2.3+)**: Implements the Model Context Protocol (MCP) standard, enabling standardized tool registration, JSON schema generation, and tool invocation.
- **Async Agent Orchestrator**: Hand-written, bounded orchestrator avoiding heavy, unpredictable frameworks like LangChain or LangGraph. Enforces hard step limits (default: 10) and per-tool timeouts (default: 60s).

---

## 3. Frontend Stack Details (`frontend/`)

### 3.1 React 19 & TypeScript 5.9
- **React 19**: Leverages modern React concurrency, transitions, and native rendering optimizations.
- **TypeScript 5.9**: Configured with strict compiler settings (`"strict": true`, `"noImplicitAny": true`) ensuring complete type alignment with backend Pydantic models.

### 3.2 Vite 8.3 Build System
- **Vite**: Provides sub-second Hot Module Replacement (HMR) during local development and optimized Rollup-based tree-shaking for production distribution.
- **Proxy Configuration**: Automatically proxies `/api` calls to `http://localhost:8000` during local development, preventing CORS friction while preserving cookie credentials.

### 3.3 Tailwind CSS v4 & Styling Engine
- **Tailwind v4**: Next-generation utility-first CSS framework featuring a high-performance Rust-based engine, CSS-first configuration (`@import "tailwindcss";`), and automatic theme tokens.
- **Color Palette**: Dark-mode-first aesthetic with slate/zinc foundations, high-contrast text, and standardized severity colors (Red for Critical/P0, Orange for High/P1, Amber for Medium/P2, Blue for Low/P3).

### 3.4 Interactive Graph Canvas (`@xyflow/react`)
- **React Flow 12.12**: Selected for rendering interactive dependency graphs:
  - Custom node components (`ExplorerNodeView.tsx`) displaying service tags, package versions, and vulnerability badges.
  - Pan, zoom, minimap, and node-dragging controls.
  - Deterministic layout calculation via `graphLayout.ts`.
  - High performance with hundreds of rendered nodes and relationships.

### 3.5 Routing & State Management
- **React Router 8.4**: Declarative client-side routing with nested layouts, error boundaries, and URL query parameter synchronization.
- **React Context**: Lightweight, specialized contexts (`ProjectProvider`, `AuthContext`) avoiding the boilerplate of external state libraries while maintaining predictable reactivity.

---

## 4. Testing & Quality Assurance Stack

### 4.1 Backend Testing (`backend/tests/`)
- **`pytest` & `pytest-asyncio`**: Asynchronous test runner validating API endpoints, Cypher queries, parser accuracy, and security boundaries.
- **`httpx.AsyncClient`**: In-memory ASGI test client for fast, end-to-end integration tests without launching separate socket listeners.

### 4.2 Frontend Testing (`frontend/src/tests/`)
- **`vitest`**: High-performance unit test runner sharing Vite's configuration and module resolution.
- **`@testing-library/react`**: Component testing adhering to user-centric testing best practices.
- **`axe-core`**: Automated WCAG accessibility audits integrated into test suites (`a11y.test.tsx`, `a11y-layout.test.tsx`, `a11y-views.test.tsx`).

---

## 5. Architectural Decisions & Trade-Offs

### FalkorDB vs. Relational (PostgreSQL) vs. Neo4j
- *Decision*: Adopt FalkorDB as the primary graph database.
- *Reasoning*: Software dependency analysis is fundamentally a path-finding problem. Evaluating transitive exposure chains in relational databases requires recursive Common Table Expressions (`WITH RECURSIVE`), which exhibit poor latency and scaling characteristics on deep trees. FalkorDB delivers graph-native Cypher traversals in under 50ms while running as a lightweight container without the JVM overhead of Neo4j.

### Hand-Written Agent Loop vs. LangChain / LangGraph
- *Decision*: Write a deterministic, hand-crafted agent loop (`orchestrator.py`) with FastMCP tools.
- *Reasoning*: Security analysis demands zero hallucinations, predictable costs, and exact step limits. Generic agent frameworks introduce large dependency trees, opaque prompt wrappers, and unpredictable retry behaviors. Vulnify's bounded loop ensures every tool call is audited, timed out, and mapped directly to FalkorDB queries.

### Cryptographic Human Gating vs. Fully Autonomous Fixes
- *Decision*: Require user approval of a SHA-256 plan hash before creating GitHub issues.
- *Reasoning*: Fully autonomous AI agents that commit code or open public bug tickets risk damaging production repositories or exposing confidential details. Gating issue creation behind a verified plan hash guarantees that only human-reviewed, non-tampered remediation plans reach GitHub.
