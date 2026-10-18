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
