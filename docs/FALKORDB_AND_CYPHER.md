# Vulnify — FalkorDB & Cypher Query Engine

> **FalkorDB Architecture, OpenCypher Semantics, Parameterized Templates, and Query Optimization**  
> *A technical guide to graph query execution, traversal bounds, and the parameterized Cypher catalog.*

---

## 1. FalkorDB Engine Overview

**FalkorDB** is an ultra-low-latency property graph database that speaks the openCypher query language while communicating over the Redis wire protocol (`RESP`).

### 1.1 Why FalkorDB for Security Graphs?
1. **Linear Algebra GraphBLAS Engine**: FalkorDB represents adjacency matrices internally as sparse linear algebra matrices. Graph traversals—such as finding reachable package dependencies—are executed as fast matrix-vector multiplications, resulting in query times typically under **10ms to 50ms**.
2. **Zero JVM Footprint**: Unlike Neo4j, FalkorDB runs as a lean C-based service inside lightweight containers (`falkordb/falkordb:latest`), consuming minimal memory.
3. **In-Memory Speed with Disk Persistence**: Operates entirely in memory for instant read/write cycles, persisting data to disk via standard Redis RDB snapshots and AOF logs.

---

## 2. Cypher Rules & Engineering Standards

All Cypher queries in Vulnify strictly adhere to the following rules:

### A. One File Per Query
Every Cypher query is isolated in its own `.cypher` file in `backend/src/vulnify/graph/queries/`. Each file begins with a mandatory header comment specifying:
- `name`: Unique identifier matching repository function.
- `what it proves`: Explicit security, dependency, or provenance assertion.
- `parameters`: Exact list of required query parameters.

### B. Strict Parameterization
**Never interpolate strings into Cypher queries.** Every dynamic argument (IDs, version strings, limits) is passed as a parameterized variable (`$param`). This completely eliminates Cypher injection vulnerabilities and enables FalkorDB query plan caching.

### C. Bounded Variable-Length Traversals
Unbounded variable-length path matching (`[:DEPENDS_ON*]`) is strictly prohibited. Every traversal must declare an explicit upper bound (e.g., `*1..8`), preventing path combinatorial explosions in cyclic or dense dependency trees.

### D. Relationship Isomorphism & Cycle Safety
Cypher inherently enforces relationship uniqueness per path (relationship isomorphism), preventing infinite loops along cyclic dependency graphs. In addition, Vulnify's Python repositories inspect node sequences to eliminate redundant cyclic re-entry paths.

---

## 3. Canonical Cypher Query Catalog

Below are key parameterized Cypher templates powering Vulnify's graph engine.

### 3.1 Bounded Dependency Path Traversal (`get_project_finding_paths.cypher`)

Traverses bounded dependency chains starting from a service entry point to a vulnerable package version, returning paths in shortest-first order.

```cypher
// name: get_project_finding_paths
// what it proves: traverses bounded dependency chains from a service to an affected package version in shortest-first order
// parameters: $service_id, $target_id, $limit
MATCH path = (s:Service {id: $service_id})-[:DEPENDS_ON*1..8]->(pv:PackageVersion {id: $target_id})
WITH path, length(path) AS depth
ORDER BY depth ASC
RETURN [n IN nodes(path) | [labels(n)[0], properties(n)]] AS path_nodes,
       [r IN relationships(path) | [type(r), properties(r)]] AS path_edges,
       depth
LIMIT $limit
```

- **Parameters**:
  - `$service_id`: `srv-auth-service`
  - `$target_id`: `npm:lodash@4.17.15`
  - `$limit`: `5` (validated: 1 to 20)
- **Output**: Array of serialized node labels and properties, edge types, and traversal depth.

---

### 3.2 Service Exposure Path Analysis (`get_project_exposure_paths.cypher`)

Evaluates complete end-to-end exposure paths, beginning at public-facing entrypoint services, crossing inter-service call boundaries (`:CALLS`), traversing dependency chains (`:DEPENDS_ON`), and terminating at affected packages linked to active advisories.

```cypher
// name: get_project_exposure_paths
// what it proves: discovers complete exposure paths from public entrypoint services to vulnerable package versions
// parameters: $project_id, $limit
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(entry:Service {public_facing: true})
OPTIONAL MATCH (entry)-[:CALLS*0..3]->(target_svc:Service)
WITH DISTINCT coalesce(target_svc, entry) AS active_svc
MATCH path = (active_svc)-[:DEPENDS_ON*1..6]->(pv:PackageVersion)<-[:AFFECTS]-(v:Vulnerability)
WITH active_svc, pv, v, path, length(path) AS depth
ORDER BY depth ASC, v.cvss DESC
RETURN active_svc.id AS service_id,
       active_svc.name AS service_name,
       pv.id AS package_version_id,
       pv.name AS package_name,
       pv.version AS installed_version,
       v.id AS advisory_id,
       v.severity AS severity,
       v.cvss AS cvss,
       depth,
       [n IN nodes(path) | properties(n).name] AS node_chain
LIMIT $limit
```

---

### 3.3 Batch Upsert Package Versions (`batch_upsert_package_versions.cypher`)

High-throughput, idempotent insertion of discovered packages during lockfile ingestion using `UNWIND`.

```cypher
// name: batch_upsert_package_versions
// what it proves: merges a batch of package version nodes into the graph
// parameters: $packages
UNWIND $packages AS pkg
MERGE (pv:PackageVersion {id: pkg.id})
ON CREATE SET pv.name = pkg.name, pv.version = pkg.version, pv.ecosystem = pkg.ecosystem, pv.purl = pkg.purl
RETURN count(pv) AS count
```

- **Parameters**: `$packages`: list of objects `[{"id": "npm:lodash@4.17.15", "name": "lodash", "version": "4.17.15", "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.15"}]`.

---

### 3.4 Batch Create Dependency Edges (`batch_create_package_dependencies.cypher`)

Creates directed dependency edges between package nodes, attaching provenance metadata and tracking which services transitively rely on each edge.

```cypher
// name: batch_create_package_dependencies
// what it proves: creates dependency relationships between package versions
// parameters: $edges
UNWIND $edges AS edge
MATCH (src:PackageVersion {id: edge.source_id})
MATCH (dst:PackageVersion {id: edge.target_id})
MERGE (src)-[r:DEPENDS_ON]->(dst)
ON CREATE SET r.direct = false, r.origin = 'manifest'
SET r.service_ids = CASE
    WHEN edge.service_id IN coalesce(r.service_ids, []) THEN r.service_ids
    ELSE coalesce(r.service_ids, []) + [edge.service_id]
END
RETURN count(r) AS count
```

---

### 3.5 Linking Vulnerability Advisories (`batch_link_package_advisories.cypher`)

Idempotently establishes bi-directional connections between package version nodes and matched OSV vulnerabilities.

```cypher
// name: batch_link_package_advisories
// what it proves: connects package version nodes to applicable vulnerability nodes
// parameters: $links
UNWIND $links AS link
MATCH (pv:PackageVersion {id: link.package_version_id})
MATCH (v:Vulnerability {id: link.advisory_id})
MERGE (pv)-[r1:HAS_ADVISORY]->(v)
ON CREATE SET r1.created_at = link.created_at, r1.origin = 'osv'
MERGE (v)-[r2:AFFECTS]->(pv)
ON CREATE SET r2.created_at = link.created_at, r2.origin = 'osv'
RETURN count(r1) AS count
```

---

### 3.6 Recording Human Triage Decisions (`record_triage_decision.cypher`)

Records human security analyst triage decisions directly onto the finding context in the graph.

```cypher
// name: record_triage_decision
// what it proves: attaches analyst triage status, reason, and timestamp to a vulnerability finding
// parameters: $project_id, $service_id, $package_version_id, $advisory_id, $status, $reason, $comment, $user_id, $updated_at
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service {id: $service_id})
MATCH (s)-[:DEPENDS_ON*1..8]->(pv:PackageVersion {id: $package_version_id})
MATCH (v:Vulnerability {id: $advisory_id})-[:AFFECTS]->(pv)
MERGE (pv)-[r:TRIAGED_UNDER {advisory_id: $advisory_id}]->(s)
SET r.status = $status,
    r.reason = $reason,
    r.comment = $comment,
    r.triaged_by = $user_id,
    r.updated_at = $updated_at
RETURN r.status AS status, r.updated_at AS updated_at
```

---

## 4. Performance & Execution Guidelines

1. **Leverage Index Lookups**: Ensure every traversal begins at an indexed property (`Service.id`, `PackageVersion.id`, `Vulnerability.id`). Never initiate traversals from unindexed property filters.
2. **Batch Ingestion with `UNWIND`**: Ingest nodes and relationships in batches of 500 items. Single-item inserts incur network roundtrip overhead; batch sizes above 2,000 increase transaction memory spikes.
3. **Deterministic Sorting**: Always order path results deterministically (`ORDER BY depth ASC, node_id ASC`) to ensure consistent pagination and reproducibility across API calls.
4. **Sub-50ms SLA**: Benchmark tests in `backend/tests/test_findings_performance.py` assert that complex path queries execute under 50ms on real-world graphs containing thousands of nodes.
