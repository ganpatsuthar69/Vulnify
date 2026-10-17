// name: batch_create_service_dependencies
// what it proves: creates direct dependency relationships from a service to root package versions
// parameters: $service_id, $dependencies
MATCH (s:Service {id: $service_id})
UNWIND $dependencies AS target_id
MATCH (target:PackageVersion {id: target_id})
MERGE (s)-[r:DEPENDS_ON]->(target)
ON CREATE SET r.direct = true, r.origin = 'manifest'
RETURN count(r) AS count
