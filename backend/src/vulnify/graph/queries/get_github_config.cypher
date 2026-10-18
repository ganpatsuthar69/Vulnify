// name: get_github_config
// what it proves: retrieves persisted GitHub target repository and credential configuration
// parameters: id

MATCH (c:GitHubConfig {id: $id})
RETURN
    c.id,
    c.owner,
    c.repo,
    c.target_repo,
    c.encrypted_token,
    c.api_base_url,
    c.validation_status,
    c.validation_message,
    c.last_validated_at,
    c.updated_at,
    c.updated_by
LIMIT 1
