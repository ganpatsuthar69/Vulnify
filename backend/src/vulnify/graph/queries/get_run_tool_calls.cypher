// name: get_run_tool_calls
// what it proves: fetches ordered tool calls executed during an AgentRun
// parameters: $run_id
MATCH (r:AgentRun {id: $run_id})-[:EXECUTED_TOOL]->(t:AgentToolCall)
RETURN t.id AS id,
       t.run_id AS run_id,
       t.sequence AS sequence,
       t.tool_name AS tool_name,
       t.display_name AS display_name,
       t.inputs_json AS inputs_json,
       t.result_summary AS result_summary,
       t.status AS status,
       t.query_id AS query_id,
       t.duration_ms AS duration_ms,
       t.outcome AS outcome,
       t.evidence_references_json AS evidence_references_json,
       t.started_at AS started_at,
       t.completed_at AS completed_at,
       t.error_message AS error_message
ORDER BY t.sequence ASC
