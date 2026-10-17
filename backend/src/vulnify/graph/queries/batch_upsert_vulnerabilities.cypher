// name: batch_upsert_vulnerabilities
// what it proves: idempotently upserts Vulnerability nodes into the graph
// parameters: $vulnerabilities
UNWIND $vulnerabilities AS v
MERGE (vuln:Vulnerability {id: v.id})
ON CREATE SET
  vuln.summary = v.summary,
  vuln.details = v.details,
  vuln.severity = v.severity,
  vuln.cvss = v.cvss,
  vuln.aliases = v.aliases,
  vuln.affected_ranges = v.affected_ranges,
  vuln.fixed_versions = v.fixed_versions,
  vuln.references = v.references,
  vuln.source_url = v.source_url,
  vuln.published = v.published,
  vuln.modified = v.modified,
  vuln.retrieved_at = v.retrieved_at,
  vuln.source = v.source
ON MATCH SET
  vuln.summary = v.summary,
  vuln.details = v.details,
  vuln.severity = v.severity,
  vuln.cvss = v.cvss,
  vuln.aliases = v.aliases,
  vuln.affected_ranges = v.affected_ranges,
  vuln.fixed_versions = v.fixed_versions,
  vuln.references = v.references,
  vuln.source_url = v.source_url,
  vuln.published = v.published,
  vuln.modified = v.modified,
  vuln.retrieved_at = v.retrieved_at
RETURN count(vuln) AS count
