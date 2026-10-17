// name: count_existing_package_dependencies
// what it proves: counts how many package-to-package dependency relationships already exist
// parameters: $edges
UNWIND $edges AS edge
MATCH (src:PackageVersion {id: edge.source_id})-[r:DEPENDS_ON]->(dst:PackageVersion {id: edge.target_id})
RETURN count(r) AS count
