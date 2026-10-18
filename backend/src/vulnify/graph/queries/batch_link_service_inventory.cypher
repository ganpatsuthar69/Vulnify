// name: batch_link_service_inventory
// what it proves: records every imported package version as part of the service inventory, including
//   modules with no known parent edge (e.g. go.mod "// indirect" requires); not a dependency path
// parameters: $service_id, $package_ids
MATCH (s:Service {id: $service_id})
UNWIND $package_ids AS package_id
MATCH (pv:PackageVersion {id: package_id})
MERGE (s)-[r:INCLUDES]->(pv)
ON CREATE SET r.origin = 'manifest'
RETURN count(r) AS count
