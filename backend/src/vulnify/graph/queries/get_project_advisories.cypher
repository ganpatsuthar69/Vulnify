// name: get_project_advisories
// what it proves: fetches distinct advisories associated with package versions in a project
// parameters: $project_id
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)-[:DEPENDS_ON|INCLUDES*1..15]->(pv:PackageVersion)-[:HAS_ADVISORY]->(v:Vulnerability)
RETURN DISTINCT
  v.id AS id,
  v.summary AS summary,
  v.details AS details,
  v.severity AS severity,
  v.cvss AS cvss,
  v.aliases AS aliases,
  v.published AS published,
  v.modified AS modified,
  v.source_url AS source_url,
  v.retrieved_at AS retrieved_at,
  pv.id AS package_version_id,
  pv.name AS package_name,
  pv.version AS package_version,
  pv.ecosystem AS ecosystem
ORDER BY v.id ASC
