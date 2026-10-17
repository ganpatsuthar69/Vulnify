// name: create_user
// what it proves: inserts a new user node into the graph with role and timestamp
// parameters: $id, $email, $name, $password_hash, $role, $created_at
CREATE (u:User {
  id: $id,
  email: $email,
  name: $name,
  password_hash: $password_hash,
  role: $role,
  created_at: $created_at
})
RETURN u.id AS id, u.email AS email, u.name AS name, u.role AS role, u.created_at AS created_at
