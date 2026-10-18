# Vulnify — Deployment & Production Operations

> **Containerization, Production Configuration, Scaling, Backup & Disaster Recovery**  
> *A comprehensive guide to deploying and operating Vulnify in production environments.*

---

## 1. Deployment Architecture

Vulnify is architected for containerized deployment across modern cloud platforms (AWS ECS/EKS, GCP Cloud Run/GKE, Azure Container Apps, or bare-metal Docker hosts).

```mermaid
flowchart TD
    Internet([Public Internet / Enterprise VPN]) --> Ingress[Ingress / Reverse Proxy\n(TLS Termination, Port 443)]

    subgraph InternalNetwork["Private Bridge Network / VPC"]
        Ingress -->|Static Assets / Client Routes| Frontend[Frontend Container\n(Nginx / Static Hosting)]
        Ingress -->|API Calls / SSE Streams| Backend[FastAPI Backend\n(Uvicorn Workers, Port 8000)]

        Backend -->|Redis Wire Protocol (Auth)| FalkorDB[(FalkorDB Graph Container\nPort 6379)]
        Backend -->|Advisory Ingestion Cache| OSVCache[(Disk Volume\n/app/.osv_cache)]
        FalkorDB -->|Graph Snapshots| DBVolume[(Persistent Volume\n/data/dump.rdb)]
    end

    Backend -.->|Outbound HTTPS| OSVAPI[OSV.dev REST API]
    Backend -.->|Outbound HTTPS| GHAPI[GitHub REST API]
```

---

## 2. Docker Compose Configuration

The root `docker-compose.yml` provides production-ready container orchestration for the FalkorDB graph engine:

```yaml
services:
  falkordb:
    image: falkordb/falkordb:latest
    container_name: vulnify-falkordb
    ports:
      - "127.0.0.1:6379:6379"
      - "127.0.0.1:3000:3000"
    volumes:
      - falkordb_data:/data
    restart: unless-stopped
    environment:
      - REDIS_ARGS=--requirepass ${FALKORDB_PASSWORD:-VulnifyLocal_ChangeMe_2026}
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${FALKORDB_PASSWORD:-VulnifyLocal_ChangeMe_2026}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  falkordb_data:
```

### Key Deployment Safeguards in Compose:
1. **Loopback Binding (`127.0.0.1`)**: Ports 6379 and 3000 are bound to localhost to prevent unintentional public exposure on multi-tenant servers.
2. **Mandatory Password Authentication**: FalkorDB runs with `--requirepass`, enforcing authentication for all client connections.
3. **Persistent Volume Storage**: Graph nodes, indexes, and relationships are persisted to the named volume `falkordb_data` at `/data`.
4. **Health Checks**: Redis `PING` command verifies container liveness every 10 seconds.

---

## 3. Production Environment Checklist

Before deploying Vulnify to a live production cluster, verify that the following configurations are set:

### 3.1 Security & Session Checklist
- [ ] **`SESSION_SECRET`**: Generated using a secure random generator (minimum 64 hex characters):
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- [ ] **`COOKIE_SECURE=true`**: Ensures that session cookies are transmitted exclusively over TLS/HTTPS.
- [ ] **`ALLOWED_ORIGINS`**: Set strictly to the production domains (e.g., `https://vulnify.your-company.com`), removing localhost origins.
- [ ] **`FALKORDB_PASSWORD`**: Replaced with a unique, high-entropy password.

### 3.2 Performance & Ingestion Checklist
- [ ] **`DEPENDENCY_IMPORT_MAX_FILE_SIZE_MB`**: Tuned to the organization's maximum expected lockfile size (default: 10 MB).
- [ ] **`OSV_CACHE_TTL_SECONDS`**: Maintained at 86400 (24 hours) to avoid hitting upstream OSV.dev rate limits.
- [ ] **`AGENT_RUN_TIMEOUT_SECONDS`**: Configured to 60-120 seconds to guarantee bounded execution.

---

## 4. Multi-Worker Backend Deployment

In production, run the FastAPI application using multiple asynchronous Uvicorn worker processes managed by a process supervisor or container manager:

```bash
uvicorn vulnify.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --proxy-headers \
  --forwarded-allow-ips="*" \
  --log-config logging_config.json
```

- **`--workers 4`**: Spawns multiple worker processes (recommended: $2 \times \text{vCPU} + 1$). Because FalkorDB handles graph state externally, FastAPI backend workers are completely stateless and horizontally scalable.
- **`--proxy-headers`**: Instructs Uvicorn to trust `X-Forwarded-Proto` and `X-Forwarded-For` headers from upstream TLS reverse proxies.

---

## 5. Frontend Production Build & Hosting

Compile the React frontend into static production assets:

```bash
cd frontend
npm run build
```

This outputs optimized HTML, CSS, and JavaScript bundles to `frontend/dist/`. Serve these files using Nginx, Caddy, or an S3/CloudFront bucket:

### Example Nginx Configuration
```nginx
server {
    listen 80;
    server_name vulnify.your-company.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vulnify.your-company.com;

    ssl_certificate /etc/ssl/certs/vulnify.crt;
    ssl_certificate_key /etc/ssl/private/vulnify.key;

    # Static Frontend Assets
    root /var/www/vulnify/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Reverse Proxy API & SSE to FastAPI Backend
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Disable buffering for Server-Sent Events (SSE)
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
    }
}
```

---

## 6. Backup, Restoration & Disaster Recovery

### 6.1 Creating a Graph Backup
Because FalkorDB runs as a RedisGraph module, the entire graph state is encapsulated within Redis RDB snapshot files:

1. **Trigger a Background Save**:
   ```bash
   docker exec -it vulnify-falkordb redis-cli -a $FALKORDB_PASSWORD BGSAVE
   ```
2. **Verify Snapshot Completion**:
   ```bash
   docker exec -it vulnify-falkordb redis-cli -a $FALKORDB_PASSWORD LASTSAVE
   ```
3. **Copy the Snapshot File**:
   ```bash
   docker cp vulnify-falkordb:/data/dump.rdb ./backups/vulnify-graph-$(date +%Y%m%d).rdb
   ```

---

### 6.2 Restoring from Backup
1. Stop the running FalkorDB container:
   ```bash
   docker compose down
   ```
2. Copy the backup snapshot into the data volume directory:
   ```bash
   cp ./backups/vulnify-graph-20261018.rdb /var/lib/docker/volumes/vulnify_falkordb_data/_data/dump.rdb
   ```
3. Restart the container:
   ```bash
   docker compose up -d
   ```

---

## 7. Monitoring & Observability

- **Application Health**: Automated monitoring tools should poll `GET /api/health` every 30 seconds.
- **Database Health**: Poll `GET /api/health/db` to verify that the graph database is responding to Cypher queries.
- **Structured JSON Logs**: FastAPI logs include `X-Request-ID`, HTTP status, execution latency, and caller IP, facilitating effortless ingestion into Datadog, Splunk, or Grafana Loki.
