// name: get_project_by_normalized_name
// what it proves: fetches a project node by its case-insensitive normalized name
// parameters: $normalized_name
MATCH (p:Project {normalized_name: $normalized_name})
RETURN p.id AS id, p.name AS name, p.ecosystem AS ecosystem, p.description AS description, p.created_at AS created_at, p.created_by AS created_by
LIMIT 1
