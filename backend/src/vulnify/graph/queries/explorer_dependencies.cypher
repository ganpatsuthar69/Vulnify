// Import evidence scopes each edge to a project service; BFS must preserve that context.
MATCH (:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)
MATCH (src:PackageVersion)-[r:DEPENDS_ON]->(dst:PackageVersion)
WHERE s.id IN coalesce(r.service_ids, [])
RETURN s.id, src, dst, r
ORDER BY s.id, src.id, dst.id
LIMIT $row_limit
