"""Repository for User entity operations against FalkorDB."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
import uuid

from vulnify.graph.client import GraphClient, get_graph_client, load_query


@dataclass
class UserRecord:
    id: str
    email: str
    name: str
    password_hash: str
    role: str
    created_at: int


class IUserRepository(Protocol):
    def get_by_email(self, email: str) -> UserRecord | None: ...
    def get_by_id(self, user_id: str) -> UserRecord | None: ...
    def create_user(self, email: str, name: str, password_hash: str, role: str = "admin") -> UserRecord: ...
    def update_role(self, email: str, role: str) -> UserRecord | None: ...


class FalkorUserRepository:
    """FalkorDB implementation of User repository."""

    def __init__(self, client: GraphClient | None = None) -> None:
        self.client = client or get_graph_client()
        self._query_create = load_query("create_user.cypher")
        self._query_get_by_email = load_query("get_user_by_email.cypher")
        self._query_get_by_id = load_query("get_user_by_id.cypher")
        self._query_update_role = load_query("update_user_role.cypher")

    def get_by_email(self, email: str) -> UserRecord | None:
        graph = self.client.get_graph()
        result = graph.query(self._query_get_by_email, {"email": email.strip().lower()})
        if not result.result_set:
            return None
        row = result.result_set[0]
        return UserRecord(
            id=str(row[0]),
            email=str(row[1]),
            name=str(row[2]),
            password_hash=str(row[3]),
            role=str(row[4]),
            created_at=int(row[5]),
        )

    def get_by_id(self, user_id: str) -> UserRecord | None:
        graph = self.client.get_graph()
        result = graph.query(self._query_get_by_id, {"id": user_id})
        if not result.result_set:
            return None
        row = result.result_set[0]
        return UserRecord(
            id=str(row[0]),
            email=str(row[1]),
            name=str(row[2]),
            password_hash=str(row[3]),
            role=str(row[4]),
            created_at=int(row[5]),
        )

    def create_user(
        self,
        email: str,
        name: str,
        password_hash: str,
        role: str = "admin",
    ) -> UserRecord:
        graph = self.client.get_graph()
        user_id = str(uuid.uuid4())
        created_at = int(datetime.now(timezone.utc).timestamp())
        cleaned_email = email.strip().lower()

        graph.query(
            self._query_create,
            {
                "id": user_id,
                "email": cleaned_email,
                "name": name.strip(),
                "password_hash": password_hash,
                "role": role,
                "created_at": created_at,
            },
        )
        return UserRecord(
            id=user_id,
            email=cleaned_email,
            name=name.strip(),
            password_hash=password_hash,
            role=role,
            created_at=created_at,
        )

    def update_role(self, email: str, role: str) -> UserRecord | None:
        graph = self.client.get_graph()
        result = graph.query(
            self._query_update_role,
            {"email": email.strip().lower(), "role": role},
        )
        if not result.result_set:
            return None
        row = result.result_set[0]
        return UserRecord(
            id=str(row[0]),
            email=str(row[1]),
            name=str(row[2]),
            password_hash="",
            role=str(row[3]),
            created_at=int(row[4]) if len(row) > 4 else 0,
        )


class InMemoryUserRepository:
    """In-memory user repository for isolated unit testing and mock mode."""

    def __init__(self) -> None:
        self._users_by_email: dict[str, UserRecord] = {}
        self._users_by_id: dict[str, UserRecord] = {}

    def get_by_email(self, email: str) -> UserRecord | None:
        return self._users_by_email.get(email.strip().lower())

    def get_by_id(self, user_id: str) -> UserRecord | None:
        return self._users_by_id.get(user_id)

    def create_user(
        self,
        email: str,
        name: str,
        password_hash: str,
        role: str = "admin",
    ) -> UserRecord:
        user_id = str(uuid.uuid4())
        now = int(datetime.now(timezone.utc).timestamp())
        record = UserRecord(
            id=user_id,
            email=email.strip().lower(),
            name=name.strip(),
            password_hash=password_hash,
            role=role,
            created_at=now,
        )
        self._users_by_email[record.email] = record
        self._users_by_id[record.id] = record
        return record

    def update_role(self, email: str, role: str) -> UserRecord | None:
        cleaned = email.strip().lower()
        if cleaned not in self._users_by_email:
            return None
        user = self._users_by_email[cleaned]
        user.role = role
        return user

    def clear(self) -> None:
        self._users_by_email.clear()
        self._users_by_id.clear()


# Default repository provider function for FastAPI dependency injection
def get_user_repository() -> IUserRepository:
    return FalkorUserRepository()
