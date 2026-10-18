// name: get_agent_runs_by_finding
// what it proves: retrieves agent runs for a project that referenced a specific finding ID
// parameters: $project_id, $finding_id, $limit
MATCH (p:Project {id: $project_id})-[:HAS_AGENT_RUN]->(r:AgentRun)
WHERE r.findings_referenced_json CONTAINS $finding_id
RETURN r.id AS id,
       r.project_id AS project_id,
       r.user_id AS user_id,
       r.user_email AS user_email,
       r.prompt AS prompt,
       r.status AS status,
       r.started_at AS started_at,
       r.completed_at AS completed_at,
       r.final_answer AS final_answer,
       r.error_message AS error_message,
       r.step_count AS step_count,
       r.findings_referenced_json AS findings_referenced_json,
       r.paths_referenced_json AS paths_referenced_json,
       r.tool_call_count AS tool_call_count
ORDER BY r.started_at DESC
LIMIT $limit
