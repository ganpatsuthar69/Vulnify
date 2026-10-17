// name: upsert_ingestion_job
// what it proves: creates or updates an IngestionJob node linked to a Project in FalkorDB
// parameters: $id, $project_id, $job_type, $status, $stage, $service_id, $service_name, $processed_items, $total_items, $percentage, $discovered_items, $created_items, $updated_items, $reused_items, $skipped_items, $failed_items, $error_summary, $errors_json, $warnings_json, $retry_eligible, $retry_of_job_id, $created_at, $started_at, $completed_at, $duration_ms, $initiated_by, $filename, $secondary_filename, $sha256_hash, $ecosystem, $import_method, $fidelity, $metadata_json
MERGE (j:IngestionJob {id: $id})
SET j.project_id = $project_id,
    j.job_type = $job_type,
    j.status = $status,
    j.stage = $stage,
    j.service_id = $service_id,
    j.service_name = $service_name,
    j.processed_items = $processed_items,
    j.total_items = $total_items,
    j.percentage = $percentage,
    j.discovered_items = $discovered_items,
    j.created_items = $created_items,
    j.updated_items = $updated_items,
    j.reused_items = $reused_items,
    j.skipped_items = $skipped_items,
    j.failed_items = $failed_items,
    j.error_summary = $error_summary,
    j.errors_json = $errors_json,
    j.warnings_json = $warnings_json,
    j.retry_eligible = $retry_eligible,
    j.retry_of_job_id = $retry_of_job_id,
    j.created_at = $created_at,
    j.started_at = $started_at,
    j.completed_at = $completed_at,
    j.duration_ms = $duration_ms,
    j.initiated_by = $initiated_by,
    j.filename = $filename,
    j.secondary_filename = $secondary_filename,
    j.sha256_hash = $sha256_hash,
    j.ecosystem = $ecosystem,
    j.import_method = $import_method,
    j.fidelity = $fidelity,
    j.metadata_json = $metadata_json
WITH j
MATCH (p:Project {id: $project_id})
MERGE (p)-[:HAS_JOB]->(j)
RETURN j.id AS id
