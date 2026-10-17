// name: remove_affects_relationship
// what it proves: removes AFFECTS relationship for package versions confirmed not affected
// parameters: $non_matches
UNWIND $non_matches AS nm
MATCH (v:Vulnerability {id: nm.advisory_id})-[r:AFFECTS]->(pv:PackageVersion {id: nm.package_version_id})
DELETE r
RETURN count(r) AS count
