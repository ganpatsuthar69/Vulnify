// name: get_project_package_versions
// what it proves: fetches distinct package versions reachable from, or inventoried by, services belonging to a project
// parameters: $project_id
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)-[:DEPENDS_ON|INCLUDES*1..15]->(pv:PackageVersion)
RETURN DISTINCT pv.id AS id, pv.name AS name, pv.version AS version, pv.ecosystem AS ecosystem, pv.purl AS purl
ORDER BY pv.name ASC, pv.version ASC
