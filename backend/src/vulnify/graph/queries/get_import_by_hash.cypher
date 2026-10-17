// name: get_import_by_hash
// what it proves: retrieves an existing import event by project, service, and file hash for idempotency checking
// parameters: $service_id, $sha256_hash
MATCH (s:Service {id: $service_id})-[:IMPORTED_FROM]->(ie:ImportEvent {sha256_hash: $sha256_hash})
RETURN ie.id AS id, ie.filename AS filename, ie.sha256_hash AS sha256_hash, ie.packages_count AS packages_count, ie.edges_count AS edges_count, ie.imported_at AS imported_at, ie.status AS status
LIMIT 1
