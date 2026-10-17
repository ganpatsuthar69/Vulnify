// name: list_projects
// what it proves: fetches all project nodes ordered by creation timestamp descending
// parameters: none
MATCH (p:Project)
RETURN p.id AS id, p.name AS name, p.ecosystem AS ecosystem, p.description AS description, p.created_at AS created_at
ORDER BY p.created_at DESC, p.name ASC
