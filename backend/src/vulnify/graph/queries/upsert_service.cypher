// name: upsert_service
// what it proves: ensures a named service node exists for a project and is linked to the project
// parameters: $project_id, $service_id, $service_name, $created_at
MATCH (p:Project {id: $project_id})
MERGE (s:Service {id: $service_id})
ON CREATE SET s.name = $service_name, s.project_id = $project_id, s.created_at = $created_at
MERGE (p)-[:HAS_SERVICE]->(s)
RETURN s.id AS id, s.name AS name
