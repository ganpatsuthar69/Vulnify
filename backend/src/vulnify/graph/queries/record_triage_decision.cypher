// name: record_triage_decision
// what it proves: updates triage status, justification, and timestamp on an AFFECTS relationship
// parameters: $project_id, $advisory_id, $package_version_id, $status, $justification, $triaged_by, $triaged_at
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)
MATCH (v:Vulnerability {id: $advisory_id})-[r:AFFECTS]->(pv:PackageVersion {id: $package_version_id})
SET r.triage_status = $status,
    r.triage_justification = $justification,
    r.triaged_by = $triaged_by,
    r.triaged_at = $triaged_at
RETURN count(r) AS updated_count
