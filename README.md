# Vulnify

> **Graph-Powered Security Investigation & Remediation Platform**  
> *Transforming flat vulnerability lists into contextual dependency exposure paths, bounded agentic investigations, and human-gated remediation.*

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![FalkorDB](https://img.shields.io/badge/FalkorDB-RedisGraph_Engine-FF4438.svg)](https://www.falkordb.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-v4.0-38B2AC.svg?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Table of Contents

- [Overview](#overview)
- [The Problem We Solve](#the-problem-we-solve)
- [Key Features](#key-features)
- [High-Level Architecture](#high-level-architecture)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
  - [1. Database Service (FalkorDB via Docker)](#1-database-service-falkordb-via-docker)
  - [2. Backend Service (FastAPI)](#2-backend-service-fastapi)
  - [3. Frontend Application (React + Vite)](#3-frontend-application-react--vite)
- [Centralized Configuration](#centralized-configuration)
- [API Documentation](#api-documentation)
- [Verification & Testing](#verification--testing)
- [Security & Trust Boundary](#security--trust-boundary)
- [Documentation Index](#documentation-index)

---

## Overview

**Vulnify** is an enterprise-ready security intelligence platform built on **FalkorDB**. Traditional software composition analysis (SCA) tools dump flat lists of hundreds of Common Vulnerabilities and Exposures (CVEs), overwhelming security teams without providing architectural context or reachability evidence. 

Vulnify models service architectures, direct dependencies, transitive dependency graphs, and Open Source Vulnerability (OSV) advisories as a unified property graph. By querying structural relationships with Cypher:
- Vulnify proves architectural **exposure paths** connecting public-facing services down to transitive libraries.
- Evaluates version ranges natively across multiple package ecosystems (npm, PyPI, Cargo, Go).
- Bounded AI agent tools investigate findings, calculate deterministic exposure priorities, and simulate upgrade blast radiuses.
- Bridges the gap to developer workflows by opening GitHub remediation issues **strictly after explicit human approval** bound to cryptographic plan hashes.

> [!IMPORTANT]
> **Safety Notice:** Bounded graph traversals demonstrate *architectural exposure* (reachability through dependency trees and service calls), not mathematical proof of exploitability. Conversely, "No path found" does not guarantee absolute safety.

---

## The Problem We Solve

| Traditional SCA Alerts | Vulnify Graph-Powered Intelligence |
| :--- | :--- |
| **Flat Vulnerability Lists:** Thousands of unranked CVE alerts with no context. | **Contextual Exposure Paths:** Directed acyclic graphs tracing entry services to vulnerable transitive packages (`:Service-[:CALLS]->:Service-[:DEPENDS_ON*]->:PackageVersion`). |
| **Hallucinating AI Copilots:** Black-box LLMs that make up CVE IDs, package versions, and auto-apply uncontrolled git commits. | **Strict Agent Gating:** Hand-written deterministic agent loop; FastMCP tools run parameterized Cypher queries; human approval gates all writes. |
| **Silent Upgrade Breakages:** Upgrading a library breaks dependent internal microservices. | **Upgrade Blast Radius Simulation:** Forward-traversal simulation calculates impact before touching production code. |
| **Context Switching to Issue Trackers:** Copy-pasting advisory text manually into Jira/GitHub. | **Cryptographically Bound Remediation:** Generates verifiable fix plans with SHA-256 hashes, dispatching to GitHub Issues via official REST APIs. |

---

## Key Features

1. **Multi-Ecosystem Lockfile Ingestion**
   - Ingests `package-lock.json` (npm v1/v2/v3), `requirements.txt` / `Pipfile.lock` / `poetry.lock` (Python), `Cargo.lock` (Rust), and `go.mod` / `go.sum` (Go).
   - Deduplicates identical imports via SHA-256 lockfile content hashing.
   - Preserves service-level provenance with `(:Service)-[:IMPORTED_FROM]->(:ImportEvent)` nodes.

2. **OSV Live Ingestion & Version Range Evaluation**
   - Integrates with the [OSV.dev API](https://osv.dev) to match vulnerabilities against exact semver and PEP 440 versions.
   - Built-in disk cache (`backend/.osv_cache`) prevents redundant external queries and rate limits.
   - Bounded batch querying with exponential backoff and retry policies.

3. **Interactive Graph Explorer Canvas**
   - High-performance, visual graph topology rendered using `@xyflow/react`.
   - Node-type badges, severity indicators, and expandable dependency trees.
   - Graph isolation per project namespace (`vulnify:{project_id}` / multi-tenant property tagging).

4. **Deterministic Priority Scoring Engine**
   - Assigns priority bands (`P0 - Critical Immediate`, `P1 - High Priority`, `P2 - Moderate Exposure`, `P3 - Low / Informational`) based on clear, transparent criteria:
     - Public entrypoint reachability.
     - Production environment classification.
     - Transitive depth.
     - Upstream CVSS/EPSS scoring.
   - Missing data is classified explicitly as `unknown` rather than artificially zero risk.

5. **Upgrade Candidates & Fix Simulation**
   - Identifies non-vulnerable upgrade versions across semver patch, minor, and major ranges.
   - Simulates dependency tree impact before applying changes, identifying potential breaking changes across shared internal services.

6. **Bounded AI Investigation Agent**
   - Lightweight, deterministic agent loop with step limits (default: 10) and per-tool timeouts.
   - Exposes read-only FastMCP tools querying FalkorDB parameterized Cypher templates.
   - Streams investigation reasoning in real-time over Server-Sent Events (SSE).
   - Zero hallucinated CVEs: all findings and packages are anchored in FalkorDB ground truth.

7. **Human-in-the-Loop GitHub Remediation**
   - Generates structured remediation issue drafts.
   - Computes a SHA-256 hash of the exact previewed remediation plan.
   - State-changing write action (`POST /api/projects/{id}/remediation/github/issues`) strictly requires user authorization matching the approved plan hash.

---

## High-Level Architecture

```
                                  +-----------------------------------------------+
                                  |            Vulnify Web Frontend              |
                                  |    (React 19, TypeScript, Vite, Tailwind)    |
                                  +-----------------------+-----------------------+
                                                          | HTTP + SSE (Cookies/CSRF)
                                                          v
                                  +-----------------------------------------------+
                                  |             FastAPI Backend Core              |
                                  |  - Lifespan & Config Validation               |
                                  |  - Argon2 Auth & Session Cookies              |
                                  |  - CSRF Middleware & Request ID Tracing       |
                                  +-----------+-----------------------+-----------+
                                              |                       |
                 +----------------------------+                       +-----------------------------+
                 |                                                                                  |
                 v                                                                                  v
+-----------------------------------+                                              +-----------------------------------+
|      FastMCP Agent Engine         |                                              |     Data Ingestion Pipeline       |
| - Read-only FalkorDB Tools        |                                              | - Parsers: npm, pip, cargo, go    |
| - Step Limits & Run Timeouts      |                                              | - OSV Live Advisory Matcher       |
| - SSE Event Streaming             |                                              | - SHA-256 Content Deduplication   |
+-----------------+-----------------+                                              +-----------------+-----------------+
                  |                                                                                  |
                  +-----------------------------------+----------------------------------------------+
                                                      |
                                                      v
                                      +-------------------------------+
                                      |      FalkorDB Graph Engine    |
                                      |  - RedisGraph Protocol (6379) |
                                      |  - Parameterized .cypher Qs   |
                                      |  - Bounded Traversal (*1..8)  |
                                      +---------------+---------------+
                                                      |
                                      +---------------+---------------+
                                      |   External Gated Integrations |
                                      |  - OSV API (https://osv.dev)  |
                                      |  - GitHub REST API v2022-11-28|
                                      +-------------------------------+
```

---

## Technology Stack

| Layer | Technologies | Version / Specifications |
| :--- | :--- | :--- |
| **Frontend** | React, TypeScript, Vite, Tailwind CSS | React 19.0, Vite 8.3, Tailwind v4, `@xyflow/react` 12.12 |
| **Backend** | Python, FastAPI, Starlette, Pydantic v2 | Python >= 3.12, FastAPI 0.115+, Pydantic-Settings |
| **Graph Database** | FalkorDB (RedisGraph protocol engine) | `falkordb/falkordb:latest` (Docker) |
| **Agent / Protocol** | FastMCP (Model Context Protocol), SSE | `mcp>=2.3.0`, Server-Sent Events |
| **Security & Auth** | Argon2id, PyJWT, Starlette BaseHTTPMiddleware | `argon2-cffi>=23.1.0`, `pyjwt>=2.8.0` |
| **Testing** | Pytest, Pytest-Asyncio, Vitest, axe-core | `pytest>=8.0.0`, `vitest>=3.0.0`, `axe-core` |

---

## Repository Structure

```
Vulnify/
├── docker-compose.yml          # Container configuration for FalkorDB
├── pyproject.toml              # Root project metadata (if applicable)
├── AGENTS.md                   # Agent guardrails and operating constraints
├── backend/
│   ├── pyproject.toml          # Backend Python dependencies & packaging
│   ├── .env.example            # Environment configuration template
│   ├── main.py                 # Backend launcher entrypoint
│   ├── src/vulnify/
│   │   ├── main.py             # FastAPI app factory, CORS, and CSRF middleware
│   │   ├── config.py           # Pydantic-Settings centralized configuration
│   │   ├── errors.py           # Standardized error responses & exception handlers
│   │   ├── logging.py          # Structured JSON logging & Request ID propagation
│   │   ├── routers/            # API route controllers (auth, projects, agent, etc.)
│   │   ├── graph/              # FalkorDB client, repositories, and Cypher queries
│   │   │   └── queries/        # 30+ parameterized .cypher query files
│   │   ├── agent/              # FastMCP tools, runner, orchestrator, schemas
│   │   │   └── tools/          # One file per MCP tool (explain, rank, open_fix_issue)
│   │   ├── services/           # Business logic (GitHub, fix simulation, scoring)
│   │   ├── version_matching/   # Semver, Cargo, Golang, and PEP 440 range evaluators
│   │   └── osv/                # OSV API client, batch querying, and disk cache
│   └── tests/                  # Pytest test suites (unit, graph, api, performance)
├── frontend/
│   ├── package.json            # Node.js dependencies & scripts
│   ├── vite.config.ts          # Vite build and proxy configuration
│   ├── .env.example            # Frontend environment variable template
│   ├── index.html              # Single-page application entry point
│   ├── src/
│   │   ├── features/           # Feature slices (explorer, intelligence, priorities, etc.)
│   │   ├── shared/             # Common UI components, API client, layouts
│   │   └── tests/              # Vitest test suites & axe-core accessibility tests
├── benchmarks/                 # Ground truth datasets, corpus, and evaluation harness
└── docs/                       # Comprehensive architectural & operational documentation
```

---

## Prerequisites

Before setting up Vulnify locally, ensure you have:

- **Docker Desktop** or Docker Engine with Docker Compose support.
- **Python 3.12+** (Python 3.12 or 3.13 recommended).
- **Node.js 20+** (LTS) and **npm 10+**.
- Modern web browser (Chrome, Firefox, Safari, Edge).

---

## Quick Start

### 1. Database Service (FalkorDB via Docker)

Start FalkorDB in the background:

```powershell
docker compose up -d
```

Verify that the container is healthy:
```powershell
docker compose ps
```
The FalkorDB instance exposes port `6379` (Redis protocol) and port `3000` (built-in FalkorDB Browser).

### 2. Backend Service (FastAPI)

Navigate to the `backend/` directory, set up your Python virtual environment, install dependencies, and configure environment variables:

```powershell
# Navigate to backend
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1
# (On macOS/Linux: source .venv/bin/activate)

# Install dependencies
pip install -e .

# Copy environment template
cp .env.example .env
```

> [!IMPORTANT]
> Edit `backend/.env` to ensure `SESSION_SECRET` is set to a secure string of at least 32 characters.

Run database health verification:
```powershell
python scripts/init_db.py  # or verify via test_database_health.py
```

Start the FastAPI development server:
```powershell
uvicorn vulnify.main:app --reload --host 127.0.0.1 --port 8000
```
Backend API will be live at `http://127.0.0.1:8000`.

### 3. Frontend Application (React + Vite)

In a separate terminal, navigate to the `frontend/` directory, install packages, and start the development server:

```powershell
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Start Vite dev server
npm run dev
```

Open your browser at `http://localhost:5173`.

---

## Centralized Configuration

Vulnify relies on strictly validated environment variables. All backend settings are centralized in [backend/src/vulnify/config.py](file:///c:/Users/ganpatsuthar/Desktop/Vulnify/backend/src/vulnify/config.py).

### Key Variables

| Variable | Default Value | Required | Description |
| :--- | :--- | :--- | :--- |
| `FALKORDB_HOST` | `localhost` | No | Hostname of the FalkorDB database instance |
| `FALKORDB_PORT` | `6379` | No | Port for FalkorDB Redis protocol |
| `FALKORDB_PASSWORD` | `VulnifyLocal_ChangeMe_2026` | No | Password for FalkorDB authentication |
| `FALKORDB_GRAPH` | `vulnify` | No | Primary graph database identifier |
| `SESSION_SECRET` | *(None)* | **Yes** | Secret key for signing session tokens (min 32 chars) |
| `SESSION_TTL_MINUTES`| `480` (8 hours) | No | Session cookie expiration time |
| `ALLOWED_ORIGINS` | `http://localhost:5173,...` | No | Permitted CORS frontend origins |
| `OSV_ENABLED` | `true` | No | Toggle live OSV advisory ingestion |
| `GITHUB_TOKEN` | *(None)* | Optional | Fine-grained PAT for opening remediation issues |
| `AGENT_LLM_PROVIDER` | `mistral` | No | LLM backend (`mistral`, `openai`, `gemini`) |
| `MISTRAL_API_KEY` | *(None)* | Optional | API key for Mistral AI reasoning models |

For the complete reference of all 30+ configuration settings, read [docs/SETUP_AND_CONFIGURATION.md](file:///c:/Users/ganpatsuthar/Desktop/Vulnify/docs/SETUP_AND_CONFIGURATION.md).

---

## API Documentation

When the backend is running, interactive OpenAPI documentation is automatically available:
- **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc UI**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Raw OpenAPI Schema**: [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

For detailed endpoint documentation, payloads, and error codes, refer to [docs/API_REFERENCE.md](file:///c:/Users/ganpatsuthar/Desktop/Vulnify/docs/API_REFERENCE.md).

---

## Verification & Testing

Vulnify enforces comprehensive quality gates across frontend and backend.

### Backend Tests
```powershell
cd backend
pytest -v
```

### Frontend Tests & Accessibility Audits
```powershell
cd frontend
npm test
npm run build
```

---

## Security & Trust Boundary

- **Untrusted Ingestion Boundaries**: Lockfiles, manifest files, and advisory text are treated as untrusted user data. They are parsed safely, sanitized, and stored as graph properties without executing code.
- **CSRF Protection**: All state-changing endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) require the custom header `X-Requested-With: vulnify` and validate caller `Origin`.
- **Argon2 Password Hashing**: User authentication uses Argon2id with cryptographically secure salts.
- **Gated Remediation**: The AI Agent cannot autonomously push commits or create external issues. Issue creation requires a matching SHA-256 plan hash signed off by a human operator.

Read [docs/SECURITY.md](file:///c:/Users/ganpatsuthar/Desktop/Vulnify/docs/SECURITY.md) for full security documentation.

---

## Documentation Index

Explore the dedicated documentation modules for in-depth technical details:

1. [Project Overview & Value Proposition](docs/PROJECT_OVERVIEW.md)
2. [System Architecture & Component Design](docs/ARCHITECTURE.md)
3. [Technology Stack & Dependency Breakdown](docs/TECH_STACK.md)
4. [Local Setup & Configuration Guide](docs/SETUP_AND_CONFIGURATION.md)
5. [Complete REST & Streaming API Reference](docs/API_REFERENCE.md)
6. [Database Schema & Property Graph Data Model](docs/DATABASE_AND_DATA_MODEL.md)
7. [FalkorDB Engine & Cypher Query Catalog](docs/FALKORDB_AND_CYPHER.md)
8. [External Integrations (OSV, GitHub, FastMCP, LLM)](docs/INTEGRATIONS.md)
9. [Security Architecture & Trust Boundaries](docs/SECURITY.md)
10. [Testing Strategy, Benchmark Suites & Quality Gates](docs/TESTING.md)
11. [Containerized Deployment & Production Operations](docs/DEPLOYMENT.md)
12. [User Guide & Platform Workflows](docs/USER_GUIDE.md)
13. [Implementation Status & Product Roadmap](docs/ROADMAP_AND_STATUS.md)

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
