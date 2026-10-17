// name: count_existing_service_dependencies
// what it proves: counts how many direct dependencies from a service to target package versions already exist
// parameters: $service_id, $target_ids
UNWIND $target_ids AS tid
MATCH (s:Service {id: $service_id})-[r:DEPENDS_ON]->(pv:PackageVersion {id: tid})
RETURN count(r) AS count
