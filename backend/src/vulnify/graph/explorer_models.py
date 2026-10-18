"""Public, allowlisted project graph explorer response contract."""

from typing import Literal

from pydantic import BaseModel, Field, JsonValue

NodeType = Literal["project", "service", "package", "advisory"]
RelationshipType = Literal["HAS_SERVICE", "DEPENDS_ON", "AFFECTS"]


class ExplorerNode(BaseModel):
    id: str
    node_type: NodeType
    label: str
    properties: dict[str, JsonValue] = Field(default_factory=dict)
    classification: Literal["direct", "transitive"] | None = None
    depth: int | None = None
    advisory_count: int = 0
    severity: str | None = None


class ExplorerEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: RelationshipType
    properties: dict[str, JsonValue] = Field(default_factory=dict)


class ProjectGraphResponse(BaseModel):
    project_id: str
    nodes: list[ExplorerNode]
    edges: list[ExplorerEdge]
    total_packages: int
    total_advisories: int
    counts_complete: bool
    has_more: bool
    next_offset: int | None
    warnings: list[str]
    root_id: str
