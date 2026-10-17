// name: record_import_event
// what it proves: records provenance for a dependency lockfile import event
// parameters: $id, $project_id, $service_id, $filename, $sha256_hash, $packages_count, $edges_count, $imported_at, $status
MATCH (s:Service {id: $service_id})
CREATE (ie:ImportEvent {
  id: $id,
  project_id: $project_id,
  service_id: $service_id,
  filename: $filename,
  sha256_hash: $sha256_hash,
  packages_count: $packages_count,
  edges_count: $edges_count,
  imported_at: $imported_at,
  status: $status
})
MERGE (s)-[:IMPORTED_FROM]->(ie)
RETURN ie.id AS id
