// name: record_triage_decision
// what it proves: records project-scoped triage status, justification, timestamp, baseline snapshot, and review status
// parameters: $project_id, $advisory_id, $package_version_id, $status, $justification, $triaged_by, $triaged_at, $baseline_data, $review_required, $review_reason, $change_category, $reviewed_at, $reviewed_by
MATCH (p:Project {id: $project_id})
MATCH (v:Vulnerability {id: $advisory_id})
MATCH (pv:PackageVersion {id: $package_version_id})
MERGE (p)-[:HAS_DECISION]->(d:TriageDecision {advisory_id: $advisory_id, package_version_id: $package_version_id})
SET d.status = $status,
    d.justification = $justification,
    d.triaged_by = $triaged_by,
    d.triaged_at = $triaged_at,
    d.baseline_data = $baseline_data,
    d.review_required = $review_required,
    d.review_reason = $review_reason,
    d.change_category = $change_category,
    d.reviewed_at = $reviewed_at,
    d.reviewed_by = $reviewed_by
RETURN count(d) AS updated_count

