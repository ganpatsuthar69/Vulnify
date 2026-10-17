// name: count_existing_advisory_links
// what it proves: checks which package-advisory links already exist
// parameters: $links
UNWIND $links AS link
MATCH (pv:PackageVersion {id: link.package_version_id})-[r:HAS_ADVISORY]->(v:Vulnerability {id: link.advisory_id})
RETURN link.package_version_id AS pvid, link.advisory_id AS aid
