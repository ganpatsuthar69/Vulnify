// Candidate IDs come only from service-context BFS. Never infer legacy edge provenance.
MATCH (:Project {id: $project_id})
UNWIND $package_ids AS package_id
MATCH (:PackageVersion {id: package_id})-[r:DEPENDS_ON]->(:PackageVersion)
WHERE size(coalesce(r.service_ids, [])) = 0
RETURN 1
LIMIT 1
