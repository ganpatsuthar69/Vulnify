// name: upsert_github_config
// what it proves: stores or updates validated GitHub integration configuration
// parameters: id, owner, repo, target_repo, encrypted_token, api_base_url, validation_status, validation_message, last_validated_at, updated_at, updated_by

MERGE (c:GitHubConfig {id: $id})
SET
    c.owner = $owner,
    c.repo = $repo,
    c.target_repo = $target_repo,
    c.encrypted_token = $encrypted_token,
    c.api_base_url = $api_base_url,
    c.validation_status = $validation_status,
    c.validation_message = $validation_message,
    c.last_validated_at = $last_validated_at,
    c.updated_at = $updated_at,
    c.updated_by = $updated_by
RETURN c.id
