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
