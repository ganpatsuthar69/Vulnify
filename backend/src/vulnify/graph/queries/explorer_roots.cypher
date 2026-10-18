// Project and real service roots, including empty projects/services. No path enumeration.
MATCH (p:Project {id: $project_id})
OPTIONAL MATCH (p)-[h:HAS_SERVICE]->(s:Service)
OPTIONAL MATCH (s)-[r:DEPENDS_ON]->(pv:PackageVersion)
RETURN p, s, h, pv, r
ORDER BY s.id, pv.id
LIMIT $row_limit
