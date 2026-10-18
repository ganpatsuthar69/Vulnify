// name: create_project
// what it proves: inserts a new project node into the graph with timestamps, normalized name, and owner
// parameters: $id, $name, $normalized_name, $ecosystem, $description, $created_at, $created_by
CREATE (p:Project {
  id: $id,
  name: $name,
  normalized_name: $normalized_name,
  ecosystem: $ecosystem,
  description: $description,
  created_at: $created_at,
  created_by: $created_by
})
RETURN p.id AS id, p.name AS name, p.ecosystem AS ecosystem, p.description AS description, p.created_at AS created_at, p.created_by AS created_by
