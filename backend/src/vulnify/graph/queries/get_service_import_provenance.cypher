// name: get_service_import_provenance
// what it proves: fetches latest lockfile import provenance for a service
// parameters: $service_id
MATCH (s:Service {id: $service_id})-[:IMPORTED_FROM]->(ie:ImportEvent)
RETURN ie.id AS import_id,
       ie.filename AS filename,
       ie.sha256_hash AS sha256_hash,
       ie.imported_at AS imported_at,
       ie.status AS status
ORDER BY ie.imported_at DESC
LIMIT 1
