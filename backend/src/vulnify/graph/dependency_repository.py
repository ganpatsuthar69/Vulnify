"""Repository for Service, PackageVersion, and Dependency graph persistence in FalkorDB."""

from datetime import datetime, timezone
from typing import Any, Protocol
import uuid

from vulnify.graph.client import GraphClient, get_graph_client, load_query
from vulnify.parsers.models import ParsedGraph
from vulnify.schemas import ImportSummaryResponse

from vulnify.utils import chunk_sequence
BATCH_CHUNK_SIZE = 500
_chunk_list = chunk_sequence


class IDependencyRepository(Protocol):
    def import_dependencies(
        self,
        project_id: str,
        service_name: str,
        filename: str,
        sha256_hash: str,
        parsed_graph: ParsedGraph,
    ) -> ImportSummaryResponse: ...

    def get_import_by_hash(
        self,
        service_id: str,
        sha256_hash: str,
    ) -> dict[str, Any] | None: ...


class FalkorDependencyRepository:
    """FalkorDB implementation for dependency graph persistence."""

    def __init__(self, client: GraphClient | None = None) -> None:
        self.client = client or get_graph_client()
        self._query_upsert_service = load_query("upsert_service.cypher")
        self._query_upsert_packages = load_query("batch_upsert_package_versions.cypher")
        self._query_create_service_deps = load_query("batch_create_service_dependencies.cypher")
        self._query_create_package_deps = load_query("batch_create_package_dependencies.cypher")
        self._query_record_import = load_query("record_import_event.cypher")
        self._query_get_by_hash = load_query("get_import_by_hash.cypher")
        self._query_count_packages = load_query("count_existing_package_versions.cypher")
        self._query_count_service_deps = load_query("count_existing_service_dependencies.cypher")
        self._query_count_package_deps = load_query("count_existing_package_dependencies.cypher")

    def get_import_by_hash(
        self,
        service_id: str,
        sha256_hash: str,
    ) -> dict[str, Any] | None:
        graph = self.client.get_graph()
        result = graph.query(
            self._query_get_by_hash,
            {"service_id": service_id, "sha256_hash": sha256_hash},
        )
        if not result.result_set:
            return None
        row = result.result_set[0]
        return {
            "id": str(row[0]),
            "filename": str(row[1]),
            "sha256_hash": str(row[2]),
            "packages_count": int(row[3]),
            "edges_count": int(row[4]),
            "imported_at": int(row[5]),
            "status": str(row[6]),
        }

    def import_dependencies(
        self,
        project_id: str,
        service_name: str,
        filename: str,
        sha256_hash: str,
        parsed_graph: ParsedGraph,
    ) -> ImportSummaryResponse:
        graph = self.client.get_graph()
        service_id = f"{project_id}:{service_name}"
        now = int(datetime.now(timezone.utc).timestamp())

        # 1. Upsert Service Node and Link to Project
        graph.query(
            self._query_upsert_service,
            {
                "project_id": project_id,
                "service_id": service_id,
                "service_name": service_name,
                "created_at": now,
            },
        )

        # 2. Count existing records to provide honest, accurate creation vs reuse metrics
        package_ids = [p.id for p in parsed_graph.packages]
        existing_packages_count = 0
        if package_ids:
            for chunk in _chunk_list(package_ids, BATCH_CHUNK_SIZE):
                res = graph.query(self._query_count_packages, {"package_ids": chunk})
                if res.result_set:
                    existing_packages_count += int(res.result_set[0][0])

        existing_service_deps_count = 0
        if parsed_graph.direct_dependency_ids:
            for chunk in _chunk_list(parsed_graph.direct_dependency_ids, BATCH_CHUNK_SIZE):
                res = graph.query(
                    self._query_count_service_deps,
                    {"service_id": service_id, "target_ids": chunk},
                )
                if res.result_set:
                    existing_service_deps_count += int(res.result_set[0][0])

        edge_params = [
            {"source_id": e.source_id, "target_id": e.target_id}
            for e in parsed_graph.edges
        ]
        existing_package_deps_count = 0
        if edge_params:
            for chunk in _chunk_list(edge_params, BATCH_CHUNK_SIZE):
                res = graph.query(self._query_count_package_deps, {"edges": chunk})
                if res.result_set:
                    existing_package_deps_count += int(res.result_set[0][0])

        total_edges_count = len(parsed_graph.direct_dependency_ids) + len(parsed_graph.edges)
        existing_edges_count = existing_service_deps_count + existing_package_deps_count

        # 3. Batch Merge PackageVersion Nodes
        package_payloads = [
            {
                "id": p.id,
                "name": p.name,
                "version": p.version,
                "ecosystem": p.ecosystem,
                "purl": p.purl,
            }
            for p in parsed_graph.packages
        ]
        for chunk in _chunk_list(package_payloads, BATCH_CHUNK_SIZE):
            graph.query(self._query_upsert_packages, {"packages": chunk})

        # 4. Batch Merge Direct Service Dependencies
        if parsed_graph.direct_dependency_ids:
            for chunk in _chunk_list(parsed_graph.direct_dependency_ids, BATCH_CHUNK_SIZE):
                graph.query(
                    self._query_create_service_deps,
                    {"service_id": service_id, "dependencies": chunk},
                )

        # 5. Batch Merge Transitive Package Dependencies
        if edge_params:
            for chunk in _chunk_list(edge_params, BATCH_CHUNK_SIZE):
                graph.query(self._query_create_package_deps, {"edges": chunk})

        # 6. Record Import Provenance Event
        import_id = str(uuid.uuid4())
        status = "completed"
        graph.query(
            self._query_record_import,
            {
                "id": import_id,
                "project_id": project_id,
                "service_id": service_id,
                "filename": filename,
                "sha256_hash": sha256_hash,
                "packages_count": len(parsed_graph.packages),
                "edges_count": total_edges_count,
                "imported_at": now,
                "status": status,
            },
        )

        packages_reused = existing_packages_count
        packages_created = max(0, len(parsed_graph.packages) - existing_packages_count)
        edges_reused = existing_edges_count
        edges_created = max(0, total_edges_count - existing_edges_count)

        return ImportSummaryResponse(
            project_id=project_id,
            service_name=service_name,
            filename=filename,
            sha256_hash=sha256_hash,
            packages_parsed=len(parsed_graph.packages),
            packages_created=packages_created,
            packages_reused=packages_reused,
            edges_created=edges_created,
            edges_reused=edges_reused,
            skipped_entries=parsed_graph.skipped_entries,
            warnings=parsed_graph.warnings,
            errors=[],
            status=status,
            imported_at=now,
        )


class InMemoryDependencyRepository:
    """In-memory dependency repository for isolated testing and mock mode."""

    def __init__(self) -> None:
        self._services: dict[str, dict[str, Any]] = {}
        self._packages: dict[str, dict[str, Any]] = {}
        self._service_deps: set[tuple[str, str]] = set()
        self._package_deps: set[tuple[str, str]] = set()
        self._imports: list[dict[str, Any]] = []

    def get_import_by_hash(
        self,
        service_id: str,
        sha256_hash: str,
    ) -> dict[str, Any] | None:
        for imp in reversed(self._imports):
            if imp["service_id"] == service_id and imp["sha256_hash"] == sha256_hash:
                return imp
        return None

    def import_dependencies(
        self,
        project_id: str,
        service_name: str,
        filename: str,
        sha256_hash: str,
        parsed_graph: ParsedGraph,
    ) -> ImportSummaryResponse:
        service_id = f"{project_id}:{service_name}"
        now = int(datetime.now(timezone.utc).timestamp())

        self._services[service_id] = {
            "id": service_id,
            "project_id": project_id,
            "name": service_name,
            "created_at": now,
        }

        # Track existing records
        packages_reused = sum(1 for p in parsed_graph.packages if p.id in self._packages)
        packages_created = len(parsed_graph.packages) - packages_reused

        service_edges_reused = sum(
            1 for target_id in parsed_graph.direct_dependency_ids
            if (service_id, target_id) in self._service_deps
        )
        package_edges_reused = sum(
            1 for edge in parsed_graph.edges
            if (edge.source_id, edge.target_id) in self._package_deps
        )
        total_edges_count = len(parsed_graph.direct_dependency_ids) + len(parsed_graph.edges)
        edges_reused = service_edges_reused + package_edges_reused
        edges_created = total_edges_count - edges_reused

        # Upsert package nodes
        for p in parsed_graph.packages:
            self._packages[p.id] = {
                "id": p.id,
                "name": p.name,
                "version": p.version,
                "ecosystem": p.ecosystem,
                "purl": p.purl,
            }

        # Upsert service edges
        for target_id in parsed_graph.direct_dependency_ids:
            self._service_deps.add((service_id, target_id))

        # Upsert package edges
        for edge in parsed_graph.edges:
            self._package_deps.add((edge.source_id, edge.target_id))

        # Record provenance
        imp = {
            "id": str(uuid.uuid4()),
            "project_id": project_id,
            "service_id": service_id,
            "filename": filename,
            "sha256_hash": sha256_hash,
            "packages_count": len(parsed_graph.packages),
            "edges_count": total_edges_count,
            "imported_at": now,
            "status": "completed",
        }
        self._imports.append(imp)

        return ImportSummaryResponse(
            project_id=project_id,
            service_name=service_name,
            filename=filename,
            sha256_hash=sha256_hash,
            packages_parsed=len(parsed_graph.packages),
            packages_created=packages_created,
            packages_reused=packages_reused,
            edges_created=edges_created,
            edges_reused=edges_reused,
            skipped_entries=parsed_graph.skipped_entries,
            warnings=parsed_graph.warnings,
            errors=[],
            status="completed",
            imported_at=now,
        )

    def clear(self) -> None:
        self._services.clear()
        self._packages.clear()
        self._service_deps.clear()
        self._package_deps.clear()
        self._imports.clear()


def get_dependency_repository() -> IDependencyRepository:
    return FalkorDependencyRepository()
