// name: get_project_package_advisories
// what it proves: fetches package versions and their associated OSV vulnerabilities with affected ranges
// parameters: $project_id
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)-[:DEPENDS_ON*1..15]->(pv:PackageVersion)-[:HAS_ADVISORY]->(v:Vulnerability)
RETURN DISTINCT
  pv.id AS package_version_id,
  pv.name AS package_name,
  pv.version AS package_version,
  pv.ecosystem AS ecosystem,
  v.id AS vulnerability_id,
  v.affected_ranges AS affected_ranges,
  v.fixed_versions AS fixed_versions,
  v.summary AS summary,
  v.severity AS severity
ORDER BY pv.name ASC, v.id ASC
