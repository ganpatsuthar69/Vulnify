// name: check_project_topology
// what it proves: checks service count and inter-service call edges in project
// parameters: $project_id
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s1:Service)
OPTIONAL MATCH (s1)-[r:CALLS]->(s2:Service)
RETURN count(DISTINCT s1) AS service_count, count(r) AS call_edge_count
