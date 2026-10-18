// name: get_project_exposure_paths
// what it proves: traverses bounded service-call topology and dependency chains from entry services to affected package versions
// parameters: $project_id, $service_id, $package_version_id, $limit
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s_affected:Service)
WHERE ($service_id IS NULL OR s_affected.id = $service_id)
MATCH dep_path = (s_affected)-[:DEPENDS_ON*1..8]->(pv:PackageVersion)
WHERE ($package_version_id IS NULL OR pv.id = $package_version_id)
MATCH (v:Vulnerability)-[aff:AFFECTS]->(pv)
WHERE aff.status = 'affected'
OPTIONAL MATCH call_path = (entry:Service)-[:CALLS*0..5]->(s_affected)
WHERE (p)-[:HAS_SERVICE]->(entry) AND entry.internet_facing = true
WITH s_affected, pv, v, aff, dep_path, call_path, entry,
     length(dep_path) AS dep_depth,
     CASE WHEN call_path IS NULL THEN 999 ELSE length(call_path) END AS call_depth
ORDER BY call_depth ASC, dep_depth ASC
RETURN s_affected.id AS affected_service_id,
       s_affected.name AS affected_service_name,
       s_affected.internet_facing AS affected_internet_facing,
       pv.id AS package_version_id,
       pv.name AS package_name,
       pv.version AS package_version,
       pv.ecosystem AS ecosystem,
       v.id AS advisory_id,
       v.severity AS severity,
       coalesce(aff.priority, v.priority, 'unknown') AS priority,
       aff.fixed_version AS fixed_version,
       entry.id AS entry_service_id,
       entry.name AS entry_service_name,
       entry.internet_facing AS entry_internet_facing,
       [n IN nodes(call_path) | [labels(n)[0], properties(n)]] AS call_nodes,
       [r IN relationships(call_path) | [type(r), properties(r)]] AS call_edges,
       [n IN nodes(dep_path) | [labels(n)[0], properties(n)]] AS dep_nodes,
       [r IN relationships(dep_path) | [type(r), properties(r)]] AS dep_edges,
       call_depth,
       dep_depth
LIMIT $limit
