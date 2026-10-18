// name: upsert_agent_run
// what it proves: creates or updates an AgentRun node and links it to Project in FalkorDB
// parameters: $id, $project_id, $user_id, $user_email, $prompt, $status, $started_at, $completed_at, $final_answer, $error_message, $step_count, $findings_referenced_json, $paths_referenced_json, $tool_call_count
MERGE (r:AgentRun {id: $id})
SET r.project_id = $project_id,
    r.user_id = $user_id,
    r.user_email = $user_email,
    r.prompt = $prompt,
    r.status = $status,
    r.started_at = $started_at,
    r.completed_at = $completed_at,
    r.final_answer = $final_answer,
    r.error_message = $error_message,
    r.step_count = $step_count,
    r.findings_referenced_json = $findings_referenced_json,
    r.paths_referenced_json = $paths_referenced_json,
    r.tool_call_count = $tool_call_count
WITH r
MATCH (p:Project {id: $project_id})
MERGE (p)-[:HAS_AGENT_RUN]->(r)
RETURN r.id AS id
