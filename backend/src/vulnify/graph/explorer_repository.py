"""Bounded, read-only graph exploration using imported service-context evidence."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
import hashlib
import json
from typing import Any

from vulnify.graph.client import GraphClient, get_graph_client, load_query
from vulnify.graph.explorer_models import (
    ExplorerEdge,
    ExplorerNode,
    NodeType,
    ProjectGraphResponse,
    RelationshipType,
)

MAX_TOPOLOGY_ROWS = 20_000
MAX_ADVISORY_ROWS = 20_000
MAX_DISPLAY_ADVISORIES = 100
QUERY_TIMEOUT_MS = 5_000

NODE_FIELDS = {
    "project": {"id", "name", "ecosystem", "description"},
    "service": {"id", "name", "internet_facing"},
    "package": {"id", "name", "version", "ecosystem", "purl"},
    "advisory": {
        "id", "source", "severity", "cvss", "affected_ranges", "references",
        "source_url", "summary", "details", "aliases", "fixed_versions",
        "published", "modified", "retrieved_at",
    },
}
DEPENDENCY_FIELDS = {"direct", "origin"}
AFFECTS_FIELDS = {
    "status", "triage_status", "matched_range", "reason", "reason_code",
    "fixed_version", "comparator", "evaluated_at", "fingerprint", "priority",
    "scoring_version", "origin",
}
JSON_FIELDS = {"affected_ranges", "references", "aliases", "fixed_versions", "matched_range"}
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "moderate": 3, "low": 2}
State = tuple[str, str]  # (raw service ID, raw package version ID)


class ExplorerNodeNotFound(LookupError):
    """The requested node is not in the verified, bounded project topology."""


def _properties(entity: Any, allowed: set[str]) -> dict[str, Any]:
    raw = entity if isinstance(entity, dict) else getattr(entity, "properties", {})
    result = {key: value for key, value in raw.items() if key in allowed and value is not None}
    for key in JSON_FIELDS & result.keys():
        if isinstance(result[key], str):
            try:
                result[key] = json.loads(result[key])
            except (ValueError, TypeError):
                pass  # Preserve real stored text when it is not JSON.
    return result


def _node(entity: Any, kind: NodeType, depth: int | None = None) -> ExplorerNode:
    props = _properties(entity, NODE_FIELDS[kind])
    raw_id = str(props["id"])
    label = str(props.get("name") or raw_id)
    if kind == "package" and props.get("name") and props.get("version"):
        label = f"{props['name']}@{props['version']}"
    return ExplorerNode(
        id=f"{kind}:{raw_id}", node_type=kind, label=label, properties=props,
        depth=depth, severity=props.get("severity") if kind == "advisory" else None,
    )


def _edge(source: str, target: str, kind: RelationshipType, props: dict[str, Any]) -> ExplorerEdge:
    key = json.dumps([source, kind, target], separators=(",", ":"))
    return ExplorerEdge(
        id=f"edge:{hashlib.sha256(key.encode()).hexdigest()}", source=source, target=target,
        relationship_type=kind, properties=props,
    )


@dataclass
class _Topology:
    nodes: dict[str, ExplorerNode] = field(default_factory=dict)
    edges: dict[str, ExplorerEdge] = field(default_factory=dict)
    parents: dict[State, State | None] = field(default_factory=dict)
    depths: dict[State, int] = field(default_factory=dict)
    package_states: dict[str, list[State]] = field(default_factory=lambda: defaultdict(list))

    def dependency(self, source: str, target: str, entity: Any, service_id: str) -> None:
        edge = _edge(source, target, "DEPENDS_ON", _properties(entity, DEPENDENCY_FIELDS))
        stored = self.edges.setdefault(edge.id, edge)
        # Never expose other projects' provenance from a shared global relationship.
        contexts = stored.properties.setdefault("service_ids", [])
        if service_id not in contexts:
            contexts.append(service_id)

    def discover(self, state: State, entity: Any, parent: State | None) -> bool:
        if state in self.parents:
            return False
        self.parents[state] = parent
        depth = 2 if parent is None else self.depths[parent] + 1
        self.depths[state] = depth
        node = _node(entity, "package", depth)
        node.classification = "direct" if parent is None else "transitive"
        # All direct roots are discovered before BFS; first discovery is shortest.
        self.nodes.setdefault(node.id, node)
        self.package_states[node.id].append(state)
        return True

    def add_paths(self, selected: set[str], root_id: str) -> set[str]:
        """Add one actual shortest root path per selected package, without enumerating paths."""
        shown = {root_id} | selected
        visited: set[State] = set()
        for node_id in sorted(selected):
            states = self.package_states.get(node_id)
            state = states[0] if states else None
            while state is not None and state not in visited:
                visited.add(state)
                service_id, package_id = state
                shown.add(f"package:{package_id}")
                shown.add(f"service:{service_id}")
                state = self.parents[state]
        return shown


def _build_topology(root_rows: list[list[Any]], dependency_rows: list[list[Any]]) -> _Topology:
    topology = _Topology()
    queue: deque[State] = deque()
    for project, service, _has_service, package, depends_on in root_rows:
        root = _node(project, "project", 0)
        topology.nodes[root.id] = root
        if service is None:
            continue
        service_node = _node(service, "service", 1)
        topology.nodes[service_node.id] = service_node
        edge = _edge(root.id, service_node.id, "HAS_SERVICE", {})
        topology.edges[edge.id] = edge
        if package is not None:
            service_id = str(service_node.properties["id"])
            package_id = str(_properties(package, {"id"})["id"])
            state = (service_id, package_id)
            if topology.discover(state, package, None):
                queue.append(state)
            topology.dependency(service_node.id, f"package:{package_id}", depends_on, service_id)

    adjacency: dict[State, list[tuple[Any, Any]]] = defaultdict(list)
    for service_id, source, target, relationship in dependency_rows:
        source_id = str(_properties(source, {"id"})["id"])
        adjacency[(service_id, source_id)].append((target, relationship))

    while queue:
        state = queue.popleft()
        service_id, source_id = state
        for target, relationship in adjacency.get(state, []):
            target_id = str(_properties(target, {"id"})["id"])
            next_state = (service_id, target_id)
            if topology.discover(next_state, target, state):
                queue.append(next_state)
            topology.dependency(
                f"package:{source_id}", f"package:{target_id}", relationship, service_id,
            )
    return topology


def _attach_advisories(
    topology: _Topology, rows: list[list[Any]], project_id: str,
) -> dict[str, set[str]]:
    affected_packages: dict[str, set[str]] = defaultdict(set)
    package_advisories: dict[str, set[str]] = defaultdict(set)
    for package_id, advisory, relationship in rows:
        target = f"package:{package_id}"
        props = _properties(relationship, AFFECTS_FIELDS)
        # Defense in depth: only verified exact-version matches may enter the response.
        if target not in topology.package_states or props.get("status") != "affected":
            continue
        if props.get("triage_status") == "not_affected":
            continue
        node = _node(advisory, "advisory")
        topology.nodes[node.id] = node
        affected_packages[node.id].add(target)
        package_advisories[target].add(node.id)
        advisory_id = node.properties["id"]
        props["finding_ids"] = sorted({
            "find-" + hashlib.sha256(
                f"{project_id}:{service_id}:{advisory_id}:{package_id}".encode()
            ).hexdigest()[:16]
            for service_id, _ in topology.package_states[target]
        })
        edge = _edge(node.id, target, "AFFECTS", props)
        topology.edges[edge.id] = edge
    for package_id, advisory_ids in package_advisories.items():
        package = topology.nodes[package_id]
        package.advisory_count = len(advisory_ids)
        severities = [topology.nodes[key].severity for key in sorted(advisory_ids)]
        package.severity = max(
            (s for s in severities if s is not None),
            key=lambda s: SEVERITY_ORDER.get(s.casefold(), 0), default=None,
        )
    return affected_packages


def _page(
    topology: _Topology, project_id: str, affected: dict[str, set[str]],
    node_id: str | None, q: str | None, offset: int, limit: int,
    warnings: list[str], counts_complete: bool,
) -> ProjectGraphResponse:
    root_id = f"project:{project_id}"
    if node_id is not None and node_id not in topology.nodes:
        raise ExplorerNodeNotFound(node_id)

    def order(key: str) -> tuple[int, str]:
        depth = topology.nodes[key].depth
        return (depth if depth is not None else MAX_TOPOLOGY_ROWS + 3, key)

    if node_id:
        candidates = set()
        for edge in topology.edges.values():
            if edge.source == node_id:
                candidates.add(edge.target)
            if edge.target == node_id:
                candidates.add(edge.source)
        candidates.discard(node_id)
    elif q and q.strip():
        candidates = set(topology.package_states) | set(affected)
    else:
        candidates = set(topology.package_states)
        if not candidates:
            candidates = {key for key, node in topology.nodes.items() if node.node_type == "service"}

    if q and q.strip():
        needle = q.strip().casefold()
        candidates = {
            key for key in candidates
            if topology.nodes[key].node_type in ("package", "advisory")
            and needle in json.dumps(topology.nodes[key].properties, ensure_ascii=False).casefold()
        }
    ordered = sorted(candidates, key=order)
    selected = set(ordered[offset:offset + limit])
    if node_id:
        selected.add(node_id)
    # Every selected advisory needs an actual affected package and its root path.
    for key in sorted(selected):
        if key in affected and not (affected[key] & selected):
            selected.add(min(affected[key], key=order))
    shown = topology.add_paths(selected, root_id)

    relevant_advisories = {
        key for key, packages in affected.items() if packages & shown
    }
    forced = shown & relevant_advisories
    additional = sorted(relevant_advisories - forced)[:max(0, MAX_DISPLAY_ADVISORIES - len(forced))]
    shown.update(additional)
    if len(relevant_advisories) > len(forced) + len(additional):
        warnings.append(
            "Advisory display is partial (maximum 100 advisory nodes). "
            "Expand a package or search advisories with offset to see more; "
            "package advisory counts and severity include all fetched matches."
        )
    edges = [
        edge for edge in topology.edges.values()
        if edge.source in shown and edge.target in shown
    ]
    has_more = offset + limit < len(ordered)
    return ProjectGraphResponse(
        project_id=project_id, root_id=root_id,
        nodes=[topology.nodes[key] for key in sorted(shown, key=order)],
        edges=sorted(edges, key=lambda edge: edge.id),
        total_packages=len(topology.package_states), total_advisories=len(affected),
        counts_complete=counts_complete, has_more=has_more,
        next_offset=offset + limit if has_more else None, warnings=warnings,
    )


class FalkorExplorerRepository:
    """Four constant batch reads; no unscoped traversal or per-node database calls."""

    def __init__(self, client: GraphClient | None = None) -> None:
        self.client = client or get_graph_client()
        self._queries = {
            name: load_query(f"explorer_{name}.cypher")
            for name in ("roots", "dependencies", "legacy", "advisories")
        }

    def get_project_graph(
        self, project_id: str, node_id: str | None = None, q: str | None = None,
        offset: int = 0, limit: int = 30,
    ) -> ProjectGraphResponse:
        if offset < 0 or not 1 <= limit <= 100:
            raise ValueError("offset must be nonnegative and limit must be between 1 and 100")
        graph = self.client.get_graph()
        warnings: list[str] = []

        def read(name: str, cap: int, **params: Any) -> list[list[Any]]:
            rows = graph.ro_query(
                self._queries[name],
                {"project_id": project_id, "row_limit": cap + 1, **params},
                timeout=QUERY_TIMEOUT_MS,
            ).result_set
            if len(rows) > cap:
                warnings.append(
                    f"The {name} read was truncated at {cap} rows; counts and search "
                    "cover only the verified fetched subset."
                )
            return rows[:cap]

        roots = read("roots", MAX_TOPOLOGY_ROWS)
        if not roots:
            raise ExplorerNodeNotFound(f"project:{project_id}")
        dependencies = read("dependencies", MAX_TOPOLOGY_ROWS)
        topology = _build_topology(roots, dependencies)
        package_ids = sorted({state[1] for state in topology.parents})
        legacy = read("legacy", 1, package_ids=package_ids)
        if legacy:
            warnings.append(
                "Legacy dependency edges without service provenance were excluded. "
                "Re-import the original dependency files for this project's services; "
                "stored import counts/hashes cannot reconstruct their topology. "
                "Counts cover only verified reachable packages and advisories."
            )
        advisories = read("advisories", MAX_ADVISORY_ROWS, package_ids=package_ids)
        affected = _attach_advisories(topology, advisories, project_id)
        return _page(
            topology, project_id, affected, node_id, q, offset, limit,
            warnings, counts_complete=not warnings,
        )


def get_explorer_repository() -> FalkorExplorerRepository:
    return FalkorExplorerRepository()
