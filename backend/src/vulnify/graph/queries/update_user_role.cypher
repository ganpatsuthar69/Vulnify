// name: update_user_role
// what it proves: updates a user's role (user/admin) in the graph
// parameters: $email, $role
MATCH (u:User {email: $email})
SET u.role = $role
RETURN u.id AS id, u.email AS email, u.name AS name, u.role AS role, u.created_at AS created_at
