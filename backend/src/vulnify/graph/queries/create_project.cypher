// name: create_project
// what it proves: inserts a new project node into the graph with timestamps and normalized name
// parameters: $id, $name, $normalized_name, $ecosystem, $description, $created_at
CREATE (p:Project {
  id: $id,
  name: $name,
  normalized_name: $normalized_name,
  ecosystem: $ecosystem,
  description: $description,
  created_at: $created_at
})
RETURN p.id AS id, p.name AS name, p.ecosystem AS ecosystem, p.description AS description, p.created_at AS created_at
