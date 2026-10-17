"""Repository for Project entity operations against FalkorDB."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
import uuid

from vulnify.graph.client import GraphClient, get_graph_client, load_query


@dataclass
class ProjectRecord:
    id: str
    name: str
    normalized_name: str
    ecosystem: str
    description: str | None
    created_at: int


class IProjectRepository(Protocol):
    def get_by_id(self, project_id: str) -> ProjectRecord | None: ...
    def get_by_normalized_name(self, normalized_name: str) -> ProjectRecord | None: ...
    def list_projects(self) -> list[ProjectRecord]: ...
    def create_project(
        self,
        name: str,
        ecosystem: str,
        description: str | None = None,
    ) -> ProjectRecord: ...


class FalkorProjectRepository:
    """FalkorDB implementation of Project repository."""

    def __init__(self, client: GraphClient | None = None) -> None:
        self.client = client or get_graph_client()
        self._query_create = load_query("create_project.cypher")
        self._query_get_by_id = load_query("get_project_by_id.cypher")
        self._query_get_by_normalized_name = load_query("get_project_by_normalized_name.cypher")
        self._query_list = load_query("list_projects.cypher")

    def get_by_id(self, project_id: str) -> ProjectRecord | None:
        graph = self.client.get_graph()
        result = graph.query(self._query_get_by_id, {"id": project_id})
        if not result.result_set:
            return None
        row = result.result_set[0]
        return ProjectRecord(
            id=str(row[0]),
            name=str(row[1]),
            normalized_name=str(row[1]).lower(),
            ecosystem=str(row[2]),
            description=str(row[3]) if row[3] is not None else None,
            created_at=int(row[4]),
        )

    def get_by_normalized_name(self, normalized_name: str) -> ProjectRecord | None:
        graph = self.client.get_graph()
        result = graph.query(
            self._query_get_by_normalized_name,
            {"normalized_name": normalized_name.strip().lower()},
        )
        if not result.result_set:
            return None
        row = result.result_set[0]
        return ProjectRecord(
            id=str(row[0]),
            name=str(row[1]),
            normalized_name=normalized_name.strip().lower(),
            ecosystem=str(row[2]),
            description=str(row[3]) if row[3] is not None else None,
            created_at=int(row[4]),
        )

    def list_projects(self) -> list[ProjectRecord]:
        graph = self.client.get_graph()
        result = graph.query(self._query_list)
        projects: list[ProjectRecord] = []
        for row in result.result_set:
            projects.append(
                ProjectRecord(
                    id=str(row[0]),
                    name=str(row[1]),
                    normalized_name=str(row[1]).lower(),
                    ecosystem=str(row[2]),
                    description=str(row[3]) if row[3] is not None else None,
                    created_at=int(row[4]),
                )
            )
        return projects

    def create_project(
        self,
        name: str,
        ecosystem: str,
        description: str | None = None,
    ) -> ProjectRecord:
        graph = self.client.get_graph()
        project_id = str(uuid.uuid4())
        cleaned_name = name.strip()
        normalized_name = cleaned_name.lower()
        cleaned_desc = description.strip() if description and description.strip() else None
        created_at = int(datetime.now(timezone.utc).timestamp())

        graph.query(
            self._query_create,
            {
                "id": project_id,
                "name": cleaned_name,
                "normalized_name": normalized_name,
                "ecosystem": ecosystem.strip(),
                "description": cleaned_desc,
                "created_at": created_at,
            },
        )
        return ProjectRecord(
            id=project_id,
            name=cleaned_name,
            normalized_name=normalized_name,
            ecosystem=ecosystem.strip(),
            description=cleaned_desc,
            created_at=created_at,
        )


class InMemoryProjectRepository:
    """In-memory project repository for isolated unit testing and mock mode."""

    def __init__(self) -> None:
        self._projects_by_id: dict[str, ProjectRecord] = {}
        self._projects_by_norm: dict[str, ProjectRecord] = {}

    def get_by_id(self, project_id: str) -> ProjectRecord | None:
        return self._projects_by_id.get(project_id)

    def get_by_normalized_name(self, normalized_name: str) -> ProjectRecord | None:
        return self._projects_by_norm.get(normalized_name.strip().lower())

    def list_projects(self) -> list[ProjectRecord]:
        items = list(self._projects_by_id.values())
        items.sort(key=lambda p: (-p.created_at, p.name))
        return items

    def create_project(
        self,
        name: str,
        ecosystem: str,
        description: str | None = None,
    ) -> ProjectRecord:
        project_id = str(uuid.uuid4())
        cleaned_name = name.strip()
        normalized_name = cleaned_name.lower()
        cleaned_desc = description.strip() if description and description.strip() else None
        now = int(datetime.now(timezone.utc).timestamp())

        record = ProjectRecord(
            id=project_id,
            name=cleaned_name,
            normalized_name=normalized_name,
            ecosystem=ecosystem.strip(),
            description=cleaned_desc,
            created_at=now,
        )
        self._projects_by_id[record.id] = record
        self._projects_by_norm[normalized_name] = record
        return record

    def clear(self) -> None:
        self._projects_by_id.clear()
        self._projects_by_norm.clear()


# Default repository provider function for FastAPI dependency injection
def get_project_repository() -> IProjectRepository:
    return FalkorProjectRepository()
