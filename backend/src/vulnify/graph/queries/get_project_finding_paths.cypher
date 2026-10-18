// name: get_project_finding_paths
// what it proves: traverses bounded dependency chains from a service to an affected package version in shortest-first order
// parameters: $service_id, $target_id, $limit
MATCH path = (s:Service {id: $service_id})-[:DEPENDS_ON*1..8]->(pv:PackageVersion {id: $target_id})
WITH path, length(path) AS depth
ORDER BY depth ASC
RETURN [n IN nodes(path) | [labels(n)[0], properties(n)]] AS path_nodes,
       [r IN relationships(path) | [type(r), properties(r)]] AS path_edges,
       depth
LIMIT $limit
