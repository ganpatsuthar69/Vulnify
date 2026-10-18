// name: get_package_dependents
// what it proves: finds all services and parent paths that depend on a package in a project
// parameters: $project_id, $package_name
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)
MATCH path = (s)-[:DEPENDS_ON*1..8]->(pv:PackageVersion)
WHERE pv.name = $package_name
RETURN DISTINCT
  s.id AS service_id,
  s.name AS service_name,
  pv.id AS package_version_id,
  pv.version AS package_version,
  min(length(path)) AS shortest_depth,
  count(path) AS total_paths
ORDER BY s.name ASC
