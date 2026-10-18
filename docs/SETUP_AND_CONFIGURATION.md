# Vulnify — Setup & Configuration Guide

> **Installation, Environment Variables, Database Initialization, and Operations**  
> *A step-by-step guide to provisioning, configuring, and verifying Vulnify.*

---

## 1. Prerequisites

Before installing Vulnify, verify that your local development environment meets the following requirements:

| Tool | Minimum Version | Recommended Version | Verification Command |
| :--- | :--- | :--- | :--- |
| **Docker** | 24.0+ | Latest Desktop / Engine | `docker --version` |
| **Docker Compose** | 2.20+ | Latest Compose v2 | `docker compose version` |
| **Python** | 3.12.0+ | 3.12 or 3.13 | `python --version` |
| **Node.js** | 20.0.0+ | 20.x or 22.x LTS | `node --version` |
| **npm** | 10.0.0+ | Latest | `npm --version` |
| **Git** | 2.40+ | Latest | `git --version` |

---

## 2. Step-by-Step Installation

### Step 2.1: Clone the Repository
```bash
git clone https://github.com/your-org/vulnify.git
cd vulnify
```

### Step 2.2: Launch FalkorDB Database via Docker
Vulnify uses **FalkorDB** as its primary graph database. The root `docker-compose.yml` configures FalkorDB with password protection and persistent storage.

```bash
docker compose up -d
```

Verify that the container is running:
```bash
docker compose ps
```
- **Redis Protocol Port**: `127.0.0.1:6379` (used by backend)
- **FalkorDB Web Browser**: `127.0.0.1:3000` (optional visual query UI)

---

### Step 2.3: Configure & Start the FastAPI Backend

1. **Navigate to the backend directory**:
   ```bash
   cd backend
   ```

2. **Create and activate a virtual environment**:
   *On Windows (PowerShell)*:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   *On macOS / Linux*:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -e .
   ```
   *Optional: Install testing dependencies*:
   ```bash
   pip install -e ".[test]"
   ```

4. **Configure environment variables**:
   ```bash
   cp .env.example .env
   ```
   Open `backend/.env` in your editor and configure `SESSION_SECRET`:
   ```env
   # Generate a 32+ char random string (e.g., using: python -c "import secrets; print(secrets.token_hex(32))")
   SESSION_SECRET=e7b4a62c90f5d18a44b1c3e80931df68a9b20e17c34d58a12401f89c47e8b23a
   ```

5. **Verify database connectivity**:
   ```bash
   python -c "from vulnify.graph.client import get_graph_client; import asyncio; asyncio.run(get_graph_client().ping())"
   ```

6. **Start the FastAPI server**:
   ```bash
   uvicorn vulnify.main:app --reload --host 127.0.0.1 --port 8000
   ```
   The backend will be available at [http://127.0.0.1:8000](http://127.0.0.1:8000).

---

### Step 2.4: Configure & Start the React Frontend

1. **In a new terminal, navigate to the frontend directory**:
   ```bash
   cd frontend
   ```

2. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

3. **Configure environment variables**:
   ```bash
   cp .env.example .env
   ```
   Default `frontend/.env` contents:
   ```env
   VITE_USE_MOCK=false
   VITE_API_BASE_URL=http://localhost:8000
   ```

4. **Start the Vite development server**:
   ```bash
   npm run dev
   ```
   The frontend will be available at [http://localhost:5173](http://localhost:5173).

---

## 3. Centralized Environment Variables Reference

All backend configuration is defined in [backend/src/vulnify/config.py](file:///c:/Users/ganpatsuthar/Desktop/Vulnify/backend/src/vulnify/config.py) using `pydantic-settings`. Values are read automatically from environment variables or `backend/.env`.

### 3.1 Database Configuration (FalkorDB)

| Variable | Type | Default | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `FALKORDB_HOST` | string | `localhost` | No | Hostname of the FalkorDB instance. |
| `FALKORDB_PORT` | integer | `6379` | No | Port for FalkorDB Redis protocol communication. |
| `FALKORDB_PASSWORD` | string | `VulnifyLocal_ChangeMe_2026` | No | Password for Redis `AUTH` command. |
| `FALKORDB_GRAPH` | string | `vulnify` | No | Base graph identifier key in FalkorDB. |
| `FALKORDB_CONNECT_TIMEOUT_SECONDS` | float | `3.0` | No | Connection timeout in seconds. |
| `FALKORDB_QUERY_TIMEOUT_MS` | integer | `5000` | No | Maximum execution time in milliseconds per Cypher query. |

---

### 3.2 Security, Authentication & Session Configuration

| Variable | Type | Default | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `SESSION_SECRET` | string | *(None)* | **YES** | Secret key for signing session tokens. **Must be >= 32 characters**; server refuses to boot otherwise. |
| `SESSION_TTL_MINUTES` | integer | `480` (8 hours) | No | Lifetime of authenticated user session cookies. |
| `COOKIE_SECURE` | boolean | `false` | No | Sets `Secure` flag on session cookies (`true` in production HTTPS). |
| `ALLOWED_ORIGINS` | string | `http://localhost:5173,http://127.0.0.1:5173` | No | Comma-separated list of allowed CORS and CSRF origins. |

---

### 3.3 Ingestion Pipeline Configuration

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `DEPENDENCY_IMPORT_MAX_FILE_SIZE_MB` | integer | `10` | Maximum upload file size in megabytes (valid: 1-100 MB). |
| `DEPENDENCY_IMPORT_MAX_PACKAGES` | integer | `5000` | Maximum package count allowed per imported lockfile. |
| `DEPENDENCY_IMPORT_BATCH_SIZE` | integer | `500` | Batch chunk size for Cypher `UNWIND` upsert queries. |

---

### 3.4 OSV Advisory Integration Configuration

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `OSV_ENABLED` | boolean | `true` | Enables live querying against OSV.dev. |
| `OSV_API_BASE_URL` | string | `https://api.osv.dev` | Base endpoint for the Open Source Vulnerabilities API. |
| `OSV_API_TIMEOUT_SECONDS` | integer | `15` | Request timeout per HTTP call to OSV. |
| `OSV_API_MAX_RETRIES` | integer | `3` | Maximum retry attempts on network/server errors. |
| `OSV_API_BACKOFF_BASE_SECONDS` | float | `1.0` | Exponential backoff multiplier between retries. |
| `OSV_CACHE_TTL_SECONDS` | integer | `86400` (24h) | Time-to-live for cached advisory responses in `backend/.osv_cache`. |
| `OSV_MAX_CONCURRENT_REQUESTS` | integer | `5` | Semaphore limit for concurrent outbound OSV API calls. |
| `OSV_BATCH_SIZE` | integer | `100` | Number of package queries bundled in `/v1/querybatch`. |

---

### 3.5 GitHub Integration Configuration

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `GITHUB_TOKEN` | string | *(None)* | Fine-grained PAT with `Issues: Read and write` permissions. |
| `GITHUB_API_BASE_URL` | string | `https://api.github.com` | Base URL for GitHub REST API calls. |
| `GITHUB_DEFAULT_OWNER` | string | `vulnify` | Default organization or username for issue dispatch. |
| `GITHUB_DEFAULT_REPO` | string | `demo-workspace` | Default repository name for issue dispatch. |
| `GITHUB_API_TIMEOUT_SECONDS` | integer | `15` | Timeout for outbound GitHub API calls. |
| `GITHUB_API_VERSION` | string | `2022-11-28` | Target GitHub REST API version header. |

---

### 3.6 AI Investigation Agent Configuration

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `AGENT_STEP_LIMIT` | integer | `10` | Hard cap on reasoning/tool iterations (valid: 1-30). |
| `AGENT_RUN_TIMEOUT_SECONDS` | integer | `60` | Total run timeout for an agent investigation (valid: 5-300s). |
| `AGENT_LLM_PROVIDER` | string | `mistral` | LLM backend: `mistral`, `openai`, or `gemini`. |
| `AGENT_LLM_MODEL` | string | `mistral-small-latest` | Model identifier passed to the LLM client. |
| `MISTRAL_API_KEY` | string | *(None)* | API key for Mistral AI services. |
| `MISTRAL_API_BASE_URL` | string | `https://api.mistral.ai/v1` | Base API URL for Mistral. |
| `OPENAI_API_KEY` | string | *(None)* | API key for OpenAI (used when provider is `openai`). |
| `GEMINI_API_KEY` | string | *(None)* | API key for Google Gemini (used when provider is `gemini`). |

---

### 3.7 Frontend Environment Variables (`frontend/.env`)

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `VITE_API_BASE_URL` | string | `http://localhost:8000` | Target backend URL for API calls. |
| `VITE_USE_MOCK` | boolean | `false` | When `false`, connects to the live FastAPI backend. |
| `VITE_MOCK_ADMIN_PASSWORD` | string | *(Empty)* | Mock authentication password (test-only, unused in production). |

---

## 4. Operational Health & Verification

Once both services are running, verify system health using standard endpoints:

### Check Backend Health
```bash
curl -s http://127.0.0.1:8000/api/health | jq
```
Expected response:
```json
{
  "status": "healthy",
  "version": "0.2.0"
}
```

### Check Database Connectivity
```bash
curl -s http://127.0.0.1:8000/api/health/db | jq
```
Expected response:
```json
{
  "status": "connected",
  "database": "FalkorDB",
  "graph": "vulnify"
}
```

---

## 5. Troubleshooting Common Issues

### Issue 1: Server refuses to start with `RuntimeError: SESSION_SECRET must be at least 32 characters`
- **Cause**: `SESSION_SECRET` is unset, empty, or shorter than 32 characters.
- **Solution**: Set a cryptographically random secret in `backend/.env`:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
  Paste the 64-character output into `SESSION_SECRET` in `backend/.env`.

### Issue 2: `redis.exceptions.ConnectionError: Error connecting to localhost:6379`
- **Cause**: FalkorDB Docker container is stopped or port 6379 is blocked.
- **Solution**: Run `docker compose up -d` in the root directory and inspect container logs:
  ```bash
  docker compose logs falkordb
  ```

### Issue 3: `CSRF_ERROR: Missing or invalid X-Requested-With header`
- **Cause**: A custom API client or script sent a mutating request (`POST`, `PUT`, `DELETE`) without the required anti-CSRF header.
- **Solution**: Include the header `X-Requested-With: vulnify` and ensure the `Origin` header matches `ALLOWED_ORIGINS`.

### Issue 4: OSV Rate Limiting or Slow Initial Ingestion
- **Cause**: Upstream OSV API latency when querying large lockfiles with thousands of packages.
- **Solution**: Vulnify automatically caches responses in `backend/.osv_cache`. Subsequent imports of the same packages will read from local disk instantaneously.
