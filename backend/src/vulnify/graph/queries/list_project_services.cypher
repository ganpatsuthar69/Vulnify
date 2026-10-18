// name: list_project_services
// what it proves: fetches distinct services belonging to a project ordered by service name
// parameters: $project_id
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)
RETURN s.id AS id, s.name AS name
ORDER BY s.name ASC
