// name: get_project_vulnerabilities
// what it proves: fetches confirmed affected vulnerabilities with their evaluation reasons for a project
// parameters: $project_id
MATCH (p:Project {id: $project_id})-[:HAS_SERVICE]->(s:Service)-[:DEPENDS_ON*1..15]->(pv:PackageVersion)<-[r:AFFECTS]-(v:Vulnerability)
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
  pv.id AS package_version_id,
  pv.name AS package_name,
  pv.version AS package_version,
  pv.ecosystem AS ecosystem,
  r.status AS match_status,
  r.reason AS match_reason,
  r.reason_code AS reason_code,
  r.matched_range AS matched_range,
  r.fixed_version AS fixed_version,
  r.evaluated_at AS evaluated_at,
  r.comparator AS comparator,
  r.fingerprint AS fingerprint
ORDER BY v.id ASC, pv.name ASC
