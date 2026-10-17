// name: count_existing_advisories
// what it proves: checks which advisory IDs already exist in FalkorDB
// parameters: $ids
UNWIND $ids AS aid
MATCH (v:Vulnerability {id: aid})
RETURN v.id AS id
