// name: get_project_findings_summary
// what it proves: aggregates confirmed vulnerability finding metrics (advisory matches, with path, without path, needing decision) for a project
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
WITH s, pv, v, r, d, min(length(path)) AS path_depth
RETURN
  count(*) AS advisory_matches,
  sum(CASE WHEN path_depth IS NOT NULL AND path_depth >= 1 THEN 1 ELSE 0 END) AS findings_with_path,
  sum(CASE WHEN path_depth IS NULL OR path_depth < 1 THEN 1 ELSE 0 END) AS findings_without_path,
  sum(CASE WHEN toLower(coalesce(d.status, r.triage_status, 'open')) IN ['open', 'under_investigation'] OR coalesce(d.review_required, r.review_required, false) = true THEN 1 ELSE 0 END) AS findings_needing_decision
