// name: get_project_findings_count
// what it proves: counts distinct confirmed vulnerability findings matching active filters for a project
// parameters: $project_id, $service_id, $search, $priority, $status
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)
MATCH path = (s)-[:DEPENDS_ON*1..8]->(pv:PackageVersion)
MATCH (v:Vulnerability)-[r:AFFECTS]->(pv)
OPTIONAL MATCH (p)-[:HAS_DECISION]->(d:TriageDecision {advisory_id: v.id, package_version_id: pv.id})
WHERE r.status = 'affected'
  AND ($service_id IS NULL OR s.id = $service_id)
  AND ($search IS NULL OR toLower(v.id) CONTAINS toLower($search) OR toLower(pv.name) CONTAINS toLower($search))
  AND ($priority IS NULL OR toLower(coalesce(r.priority, v.priority, 'unknown')) = toLower($priority))
  AND ($status IS NULL OR toLower(coalesce(d.status, r.triage_status, 'open')) = toLower($status))
WITH DISTINCT s, pv, v
RETURN count(*) AS total
