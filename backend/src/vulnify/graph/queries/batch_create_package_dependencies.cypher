// name: batch_create_package_dependencies
// what it proves: creates dependency relationships between package versions
// parameters: $edges
UNWIND $edges AS edge
MATCH (src:PackageVersion {id: edge.source_id})
MATCH (dst:PackageVersion {id: edge.target_id})
MERGE (src)-[r:DEPENDS_ON]->(dst)
ON CREATE SET r.direct = false, r.origin = 'manifest'
RETURN count(r) AS count
