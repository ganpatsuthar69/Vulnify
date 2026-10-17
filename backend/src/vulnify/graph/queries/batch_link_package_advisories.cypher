// name: batch_link_package_advisories
// what it proves: connects package version nodes to applicable vulnerability nodes
// parameters: $links
UNWIND $links AS link
MATCH (pv:PackageVersion {id: link.package_version_id})
MATCH (v:Vulnerability {id: link.advisory_id})
MERGE (pv)-[r1:HAS_ADVISORY]->(v)
ON CREATE SET r1.created_at = link.created_at, r1.origin = 'osv'
MERGE (v)-[r2:AFFECTS]->(pv)
ON CREATE SET r2.created_at = link.created_at, r2.origin = 'osv'
RETURN count(r1) AS count
