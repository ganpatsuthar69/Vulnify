// name: count_agent_runs
// what it proves: counts total AgentRuns for a project
// parameters: $project_id
MATCH (p:Project {id: $project_id})-[:HAS_AGENT_RUN]->(r:AgentRun)
RETURN count(r) AS total
