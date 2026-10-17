// name: batch_upsert_package_versions
// what it proves: merges a batch of package version nodes into the graph
// parameters: $packages
UNWIND $packages AS pkg
MERGE (pv:PackageVersion {id: pkg.id})
ON CREATE SET pv.name = pkg.name, pv.version = pkg.version, pv.ecosystem = pkg.ecosystem, pv.purl = pkg.purl
RETURN count(pv) AS count
