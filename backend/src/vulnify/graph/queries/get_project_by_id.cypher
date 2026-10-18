// name: get_project_by_id
// what it proves: fetches a project node by its unique identifier
// parameters: $id
MATCH (p:Project {id: $id})
RETURN p.id AS id, p.name AS name, p.ecosystem AS ecosystem, p.description AS description, p.created_at AS created_at, p.created_by AS created_by
LIMIT 1
