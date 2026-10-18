// name: upsert_affects_relationship
// what it proves: idempotently records or updates an AFFECTS relationship with evaluation metadata
// parameters: $matches
UNWIND $matches AS m
MATCH (v:Vulnerability {id: m.advisory_id})
MATCH (pv:PackageVersion {id: m.package_version_id})
MERGE (v)-[r:AFFECTS]->(pv)
SET r.status = m.status,
    r.reason = m.reason,
    r.reason_code = m.reason_code,
    r.matched_range = m.matched_range,
    r.fixed_version = m.fixed_version,
    r.comparator = m.comparator,
    r.evaluated_at = m.evaluated_at,
    r.fingerprint = m.fingerprint,
    r.priority = m.priority,
    r.scoring_version = m.scoring_version,
    r.origin = 'version_match'
RETURN count(r) AS count
