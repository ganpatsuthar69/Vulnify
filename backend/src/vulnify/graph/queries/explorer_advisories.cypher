// Exact candidate version IDs are verified by project/service-context BFS, not package names.
MATCH (:Project {id: $project_id})
UNWIND $package_ids AS package_id
MATCH (v:Vulnerability)-[r:AFFECTS]->(pv:PackageVersion {id: package_id})
WHERE r.status = 'affected' AND coalesce(r.triage_status, '') <> 'not_affected'
RETURN pv.id, v, r
ORDER BY pv.id, v.id
LIMIT $row_limit
