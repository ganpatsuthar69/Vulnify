// name: upsert_agent_tool_call
// what it proves: creates or updates an AgentToolCall node and links it to parent AgentRun
// parameters: $id, $run_id, $sequence, $tool_name, $display_name, $inputs_json, $result_summary, $status, $query_id, $duration_ms, $outcome, $evidence_references_json, $started_at, $completed_at, $error_message
MERGE (t:AgentToolCall {id: $id})
SET t.run_id = $run_id,
    t.sequence = $sequence,
    t.tool_name = $tool_name,
    t.display_name = $display_name,
    t.inputs_json = $inputs_json,
    t.result_summary = $result_summary,
    t.status = $status,
    t.query_id = $query_id,
    t.duration_ms = $duration_ms,
    t.outcome = $outcome,
    t.evidence_references_json = $evidence_references_json,
    t.started_at = $started_at,
    t.completed_at = $completed_at,
    t.error_message = $error_message
WITH t
MATCH (r:AgentRun {id: $run_id})
MERGE (r)-[:EXECUTED_TOOL {sequence: $sequence}]->(t)
RETURN t.id AS id
