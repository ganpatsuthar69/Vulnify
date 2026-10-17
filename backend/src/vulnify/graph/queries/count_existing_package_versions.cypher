// name: count_existing_package_versions
// what it proves: counts how many package versions from a list of IDs already exist in the graph
// parameters: $package_ids
UNWIND $package_ids AS pid
MATCH (pv:PackageVersion {id: pid})
RETURN count(pv) AS count
