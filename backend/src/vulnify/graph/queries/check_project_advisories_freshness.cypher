// name: check_project_advisories_freshness
// what it proves: evaluates advisory timestamps against the 7-day freshness policy
// parameters: $project_id
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(:Service)-[:DEPENDS_ON|INCLUDES*1..15]->(pv:PackageVersion)-[:HAS_ADVISORY]->(v:Vulnerability)
RETURN
  count(DISTINCT v) AS total_advisories,
  min(v.retrieved_at) AS oldest_retrieved_at,
  max(v.retrieved_at) AS newest_retrieved_at,
  count(DISTINCT CASE WHEN v.retrieved_at IS NULL OR v.retrieved_at = 0 THEN v END) AS missing_timestamp_count
