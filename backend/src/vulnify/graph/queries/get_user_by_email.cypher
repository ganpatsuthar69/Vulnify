// name: get_user_by_email
// what it proves: fetches a user record by exact email match
// parameters: $email
MATCH (u:User {email: $email})
RETURN u.id AS id, u.email AS email, u.name AS name, u.password_hash AS password_hash, u.role AS role, u.created_at AS created_at
LIMIT 1
