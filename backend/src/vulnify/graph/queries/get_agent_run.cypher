// name: get_agent_run
// what it proves: fetches single AgentRun by project_id and run_id
// parameters: $project_id, $run_id
MATCH (p:Project {id: $project_id})-[:HAS_AGENT_RUN]->(r:AgentRun {id: $run_id})
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
