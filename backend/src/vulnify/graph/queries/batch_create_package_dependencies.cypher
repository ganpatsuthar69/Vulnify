// name: batch_create_package_dependencies
// what it proves: creates dependency relationships between package versions
// parameters: $edges
UNWIND $edges AS edge
MATCH (src:PackageVersion {id: edge.source_id})
MATCH (dst:PackageVersion {id: edge.target_id})
MERGE (src)-[r:DEPENDS_ON]->(dst)
ON CREATE SET r.direct = false, r.origin = 'manifest'
// Only this imported edge is evidence for this service, including existing global edges.
SET r.service_ids = CASE
    WHEN edge.service_id IN coalesce(r.service_ids, []) THEN r.service_ids
    ELSE coalesce(r.service_ids, []) + [edge.service_id]
END
RETURN count(r) AS count
