"""Repository for persisting and retrieving GitHub integration configuration in FalkorDB (US-506).

Responsibilities:
1. Durable persistence of administrative target repository (owner/repo) and encrypted credentials.
2. Separation of non-sensitive target configuration from encrypted personal access tokens.
3. Support for global application defaults and optional project-level repository overrides.
4. Retention of last validation status, timestamp, and audit actor.
5. In-memory implementation for isolated unit testing and mock mode.
"""

from dataclasses import dataclass
from typing import Protocol
import logging

from vulnify.graph.client import GraphClient, get_graph_client, load_query

logger = logging.getLogger("vulnify")


@dataclass
class GitHubConfigRecord:
    """Persisted GitHub configuration record."""

    id: str  # "global" or project_id
    owner: str
    repo: str
    target_repo: str
    encrypted_token: str | None
    api_base_url: str
    validation_status: str | None  # "valid", "invalid", "unconfigured", etc.
    validation_message: str | None
    last_validated_at: int | None
    updated_at: int
    updated_by: str | None


class IGitHubConfigRepository(Protocol):
    """Interface for GitHub configuration persistence."""

    def get_config(self, config_id: str = "global") -> GitHubConfigRecord | None: ...
    def upsert_config(self, record: GitHubConfigRecord) -> GitHubConfigRecord: ...
    def delete_config(self, config_id: str = "global") -> bool: ...
    def clear(self) -> None: ...


class FalkorGitHubConfigRepository:
    """FalkorDB implementation of GitHub configuration repository."""

    def __init__(self, client: GraphClient | None = None) -> None:
        self.client = client or get_graph_client()
        self._query_get = load_query("get_github_config.cypher")
        self._query_upsert = load_query("upsert_github_config.cypher")
        self._query_delete = load_query("delete_github_config.cypher")

    def get_config(self, config_id: str = "global") -> GitHubConfigRecord | None:
        try:
            graph = self.client.get_graph()
            result = graph.query(self._query_get, {"id": config_id})
            if not result.result_set:
                return None
            row = result.result_set[0]
            return GitHubConfigRecord(
                id=str(row[0]),
                owner=str(row[1]),
                repo=str(row[2]),
                target_repo=str(row[3]),
                encrypted_token=str(row[4]) if row[4] is not None else None,
                api_base_url=str(row[5]),
                validation_status=str(row[6]) if row[6] is not None else None,
                validation_message=str(row[7]) if row[7] is not None else None,
                last_validated_at=int(row[8]) if row[8] is not None else None,
                updated_at=int(row[9]),
                updated_by=str(row[10]) if row[10] is not None else None,
            )
        except Exception as exc:
            logger.warning("Failed to retrieve GitHub config from FalkorDB: %s", exc)
            return None

    def upsert_config(self, record: GitHubConfigRecord) -> GitHubConfigRecord:
        graph = self.client.get_graph()
        graph.query(
            self._query_upsert,
            {
                "id": record.id,
                "owner": record.owner,
                "repo": record.repo,
                "target_repo": record.target_repo,
                "encrypted_token": record.encrypted_token,
                "api_base_url": record.api_base_url,
                "validation_status": record.validation_status,
                "validation_message": record.validation_message,
                "last_validated_at": record.last_validated_at,
                "updated_at": record.updated_at,
                "updated_by": record.updated_by,
            },
        )
        return record

    def delete_config(self, config_id: str = "global") -> bool:
        try:
            graph = self.client.get_graph()
            graph.query(self._query_delete, {"id": config_id})
            return True
        except Exception as exc:
            logger.warning("Failed to delete GitHub config from FalkorDB: %s", exc)
            return False

    def clear(self) -> None:
        self.delete_config("global")


class InMemoryGitHubConfigRepository:
    """In-memory implementation for isolated unit testing and fallback."""

    def __init__(self) -> None:
        self._configs: dict[str, GitHubConfigRecord] = {}

    def get_config(self, config_id: str = "global") -> GitHubConfigRecord | None:
        return self._configs.get(config_id)

    def upsert_config(self, record: GitHubConfigRecord) -> GitHubConfigRecord:
        self._configs[record.id] = record
        return record

    def delete_config(self, config_id: str = "global") -> bool:
        if config_id in self._configs:
            del self._configs[config_id]
            return True
        return False

    def clear(self) -> None:
        self._configs.clear()


# Default provider function and test override hook
_repository_override: IGitHubConfigRepository | None = None


def get_github_config_repository() -> IGitHubConfigRepository:
    """FastAPI dependency for accessing the configured GitHubConfig repository."""
    if _repository_override is not None:
        return _repository_override
    try:
        return FalkorGitHubConfigRepository()
    except Exception:
        # Graceful fallback to in-memory if FalkorDB connection fails
        return InMemoryGitHubConfigRepository()


def set_github_config_repository_override(repo: IGitHubConfigRepository | None) -> None:
    """Override repository singleton (used in test fixtures)."""
    global _repository_override
    _repository_override = repo
