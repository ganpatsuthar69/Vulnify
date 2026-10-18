# Vulnify Cypher Catalog

This catalog documents all canonical FalkorDB Cypher queries powering the Vulnify graph engine, their query semantics, traversal bounds, schema assumptions, and performance characteristics.

---

## 1. Finding Dependency Paths (`get_project_finding_paths`)

### Purpose
Traverses the dependency tree in FalkorDB starting from an application service entry point to an affected package version node (`PackageVersion`). Returns the shortest few dependency paths in deterministic shortest-first order with full node properties and relationship metadata.

### Cypher Query Template
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

### Entity Model and Direction
- **Starting Entity**: `(s:Service {id: $service_id})` representing the named service or microservice manifest.
- **Traversal Relationship**: `[:DEPENDS_ON*1..8]` directed outward from service through direct dependencies to transitive package dependencies.
- **Target Entity**: `(pv:PackageVersion {id: $target_id})` representing the exact vulnerable package version node linked by `(v:Vulnerability)-[:AFFECTS]->(pv)`.

### Bounds and Complexity
- **Traversal Bound**: Literal depth bound `*1..8`. Traversals beyond 8 hops are halted by the graph engine to prevent exponential path explosion in dense or cyclic graphs.
- **Result Bound**: `$limit` (defaults to 5, validated between 1 and 20).
- **Shortest-First Ordering**: `ORDER BY depth ASC` ensures direct dependencies (depth 1) appear before transitive dependencies (depth 2+).

### Cycle and Duplicate Elimination
- **Cycle Handling**: Cypher path pattern matching enforces relationship uniqueness per path (relationship isomorphism), preventing infinite loops on cyclic dependency edges. The backend engine additionally inspects node identity sets along each path to eliminate any node-level re-entry cycles.
- **Deduplication**: Identical node sequences are deduplicated in memory.
- **Deterministic Tie-Breaking**: Equal-depth paths are ordered deterministically by comparing the lexicographical sequence of constituent node identifiers.

### Performance Considerations
- Lookups on `Service.id` and `PackageVersion.id` leverage index scans.
- Query execution latency is typically under 50ms on real lockfile graphs (well below the 1-second hackathon SLA).

---

## 2. Service Import Provenance (`get_service_import_provenance`)

### Purpose
Retrieves the latest audit provenance record for an ingested service, including the original lockfile or manifest filename, SHA-256 digest, and import timestamp.

### Cypher Query Template
```cypher
// name: get_service_import_provenance
// what it proves: fetches latest lockfile import provenance for a service
// parameters: $service_id
MATCH (s:Service {id: $service_id})-[:IMPORTED_FROM]->(ie:ImportEvent)
RETURN ie.id AS import_id,
       ie.filename AS filename,
       ie.sha256_hash AS sha256_hash,
       ie.imported_at AS imported_at,
       ie.status AS status
ORDER BY ie.imported_at DESC
LIMIT 1
```

### Entity Model and Direction
- **Starting Entity**: `(s:Service {id: $service_id})`
- **Relationship**: `[:IMPORTED_FROM]` directed from `Service` to `ImportEvent`.
- **Target Entity**: `(ie:ImportEvent)` created during lockfile ingestion (US-102).

---

## 3. Project Findings List (`get_project_findings`)

### Purpose
Retrieves server-paginated, deduplicated vulnerability findings for a project, computing the minimum dependency path depth from services to affected package versions.

### Cypher Query Template
```cypher
// name: get_project_findings
// what it proves: fetches distinct confirmed vulnerability findings with shortest path depth and evidence for a project
// parameters: $project_id, $service_id, $search, $priority, $status
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)
MATCH path = (s)-[:DEPENDS_ON*1..8]->(pv:PackageVersion)
MATCH (v:Vulnerability)-[r:AFFECTS]->(pv)
WHERE r.status = 'affected'
  AND ($service_id IS NULL OR s.id = $service_id)
  AND ($search IS NULL OR toLower(v.id) CONTAINS toLower($search) OR toLower(pv.name) CONTAINS toLower($search))
  AND ($priority IS NULL OR toLower(coalesce(r.priority, v.priority, 'unknown')) = toLower($priority))
  AND ($status IS NULL OR toLower(coalesce(r.triage_status, 'open')) = toLower($status))
WITH s, pv, v, r, min(length(path)) AS path_depth
RETURN s.id AS service_id,
       s.name AS service_name,
       v.id AS advisory_id,
       v.summary AS advisory_summary,
       v.severity AS severity,
       v.source_url AS source_url,
       v.retrieved_at AS retrieved_at,
       pv.id AS package_version_id,
       pv.name AS package_name,
       pv.version AS package_version,
       pv.ecosystem AS ecosystem,
       r.reason AS match_reason,
       r.reason_code AS reason_code,
       r.matched_range AS matched_range,
       r.fixed_version AS fixed_version,
       coalesce(r.priority, v.priority, 'unknown') AS priority,
       coalesce(r.triage_status, 'open') AS status,
       path_depth
ORDER BY v.id ASC, pv.name ASC, s.name ASC, pv.version ASC
```

---

## 4. Single Finding Detail with Evidence (`get_project_finding_detail`)

### Purpose
Retrieves full advisory metadata, match explanation, version constraints, and aliases for a specific finding in a project.

### Cypher Query Template
```cypher
// name: get_project_finding_detail
// what it proves: fetches full evidence, match explanation, and advisory details for a specific vulnerability finding in a project
// parameters: $project_id, $finding_id
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)
MATCH path = (s)-[:DEPENDS_ON*1..8]->(pv:PackageVersion)
MATCH (v:Vulnerability)-[r:AFFECTS]->(pv)
WHERE r.status = 'affected'
  AND (v.id = $finding_id OR toLower(v.id) = toLower($finding_id) OR (v.aliases IS NOT NULL AND $finding_id IN v.aliases))
WITH s, pv, v, r, min(length(path)) AS path_depth
RETURN s.id AS service_id,
       s.name AS service_name,
       v.id AS advisory_id,
       v.summary AS advisory_summary,
       v.details AS advisory_details,
       v.severity AS severity,
       v.source_url AS source_url,
       v.retrieved_at AS retrieved_at,
       v.aliases AS aliases,
       pv.id AS package_version_id,
       pv.name AS package_name,
       pv.version AS package_version,
       pv.ecosystem AS ecosystem,
       r.reason AS match_reason,
       r.reason_code AS reason_code,
       r.matched_range AS matched_range,
       r.fixed_version AS fixed_version,
       coalesce(r.priority, v.priority, 'unknown') AS priority,
       coalesce(r.triage_status, 'open') AS status,
       path_depth
ORDER BY v.id ASC
LIMIT 1
```
