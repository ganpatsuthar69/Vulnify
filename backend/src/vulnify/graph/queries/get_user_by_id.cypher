// name: get_user_by_id
// what it proves: fetches a user record by unique identifier
// parameters: $id
MATCH (u:User {id: $id})
RETURN u.id AS id, u.email AS email, u.name AS name, u.password_hash AS password_hash, u.role AS role, u.created_at AS created_at
LIMIT 1
