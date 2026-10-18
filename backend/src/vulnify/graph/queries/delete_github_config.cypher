// name: delete_github_config
// what it proves: deletes persisted GitHub integration configuration
// parameters: id

MATCH (c:GitHubConfig {id: $id})
DELETE c
RETURN count(c)
