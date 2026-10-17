"""Repository for Vulnerability nodes and package-advisory relationships in FalkorDB."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any, Protocol

from vulnify.graph.client import GraphClient, get_graph_client, load_query

from vulnify.models import AdvisoryLinkRecord, PackageVersion, VulnerabilityRecord
from vulnify.utils import chunk_sequence

CHUNK_SIZE = 500

# Backward compatibility alias
PackageVersionItem = PackageVersion
_chunk_list = chunk_sequence


class IAdvisoryRepository(Protocol):
    def get_project_package_versions(self, project_id: str) -> list[PackageVersionItem]: ...

    def persist_advisories(
        self,
        vulnerabilities: list[VulnerabilityRecord],
        links: list[AdvisoryLinkRecord],
    ) -> tuple[int, int, int, int]: ...

    def get_project_advisories(self, project_id: str) -> list[dict[str, Any]]: ...


class FalkorAdvisoryRepository:
    """FalkorDB implementation of Advisory and Vulnerability persistence."""

    def __init__(self, client: GraphClient | None = None) -> None:
        self.client = client or get_graph_client()
        self._query_get_package_versions = load_query("get_project_package_versions.cypher")
        self._query_upsert_vulns = load_query("batch_upsert_vulnerabilities.cypher")
        self._query_link_vulns = load_query("batch_link_package_advisories.cypher")
        self._query_count_existing_vulns = load_query("count_existing_advisories.cypher")
        self._query_count_existing_links = load_query("count_existing_advisory_links.cypher")
        self._query_get_advisories = load_query("get_project_advisories.cypher")

    def get_project_package_versions(self, project_id: str) -> list[PackageVersionItem]:
        graph = self.client.get_graph()
        result = graph.query(self._query_get_package_versions, {"project_id": project_id})
        items: list[PackageVersionItem] = []
        for row in result.result_set:
            items.append(
                PackageVersionItem(
                    id=str(row[0]),
                    name=str(row[1]),
                    version=str(row[2]),
                    ecosystem=str(row[3]),
                    purl=str(row[4]) if row[4] is not None else "",
                )
            )
        return items

    def persist_advisories(
        self,
        vulnerabilities: list[VulnerabilityRecord],
        links: list[AdvisoryLinkRecord],
    ) -> tuple[int, int, int, int]:
        """Idempotently persist vulnerabilities and relationships in FalkorDB.
        
        Returns:
            tuple of (advisories_created, advisories_updated, links_created, links_reused)
        """
        if not vulnerabilities and not links:
            return 0, 0, 0, 0

        graph = self.client.get_graph()

        # 1. Determine which vulnerabilities already exist
        vuln_ids = [v.id for v in vulnerabilities]
        existing_vuln_ids: set[str] = set()
        if vuln_ids:
            for chunk in _chunk_list(vuln_ids, CHUNK_SIZE):
                res = graph.query(self._query_count_existing_vulns, {"ids": chunk})
                for row in res.result_set:
                    existing_vuln_ids.add(str(row[0]))

        advisories_created = len(vuln_ids) - len(existing_vuln_ids)
        advisories_updated = len(existing_vuln_ids)

        # 2. Batch upsert Vulnerability nodes
        vuln_payloads = [
            {
                "id": v.id,
                "summary": v.summary,
                "details": v.details,
                "severity": v.severity,
                "cvss": v.cvss or "",
                "aliases": v.aliases,
                "affected_ranges": v.affected_ranges,
                "fixed_versions": v.fixed_versions,
                "references": v.references,
                "source_url": v.source_url,
                "published": v.published or "",
                "modified": v.modified or "",
                "retrieved_at": v.retrieved_at,
                "source": v.source,
            }
            for v in vulnerabilities
        ]
        for chunk in _chunk_list(vuln_payloads, CHUNK_SIZE):
            graph.query(self._query_upsert_vulns, {"vulnerabilities": chunk})

        # 3. Determine which links already exist
        link_payloads = [
            {
                "package_version_id": l.package_version_id,
                "advisory_id": l.advisory_id,
                "created_at": l.created_at,
            }
            for l in links
        ]
        existing_links: set[tuple[str, str]] = set()
        if link_payloads:
            for chunk in _chunk_list(link_payloads, CHUNK_SIZE):
                res = graph.query(self._query_count_existing_links, {"links": chunk})
                for row in res.result_set:
                    existing_links.add((str(row[0]), str(row[1])))

        links_reused = len(existing_links)
        links_created = len(links) - links_reused

        # 4. Batch link package versions to vulnerabilities
        for chunk in _chunk_list(link_payloads, CHUNK_SIZE):
            graph.query(self._query_link_vulns, {"links": chunk})

        return advisories_created, advisories_updated, links_created, links_reused

    def get_project_advisories(self, project_id: str) -> list[dict[str, Any]]:
        graph = self.client.get_graph()
        result = graph.query(self._query_get_advisories, {"project_id": project_id})
        advisories: list[dict[str, Any]] = []
        for row in result.result_set:
            raw_aliases = row[5]
            aliases: list[str] = list(raw_aliases) if isinstance(raw_aliases, (list, tuple)) else []
            advisories.append(
                {
                    "id": str(row[0]),
                    "summary": str(row[1]),
                    "details": str(row[2]) if row[2] is not None else "",
                    "severity": str(row[3]) if row[3] is not None else "UNKNOWN",
                    "cvss": str(row[4]) if row[4] else None,
                    "aliases": aliases,
                    "published": str(row[6]) if row[6] else None,
                    "modified": str(row[7]) if row[7] else None,
                    "source_url": str(row[8]) if row[8] else "",
                    "retrieved_at": int(row[9]),
                    "package_version_id": str(row[10]),
                    "package_name": str(row[11]),
                    "package_version": str(row[12]),
                    "ecosystem": str(row[13]),
                }
            )
        return advisories


class InMemoryAdvisoryRepository:
    """In-memory advisory repository for unit testing and mock mode."""

    def __init__(self) -> None:
        self._package_versions_by_project: dict[str, list[PackageVersionItem]] = {}
        self._vulnerabilities: dict[str, VulnerabilityRecord] = {}
        self._links: set[tuple[str, str]] = set()
        self._link_records: list[AdvisoryLinkRecord] = []

    def set_project_packages(self, project_id: str, packages: list[PackageVersionItem]) -> None:
        self._package_versions_by_project[project_id] = list(packages)

    def get_project_package_versions(self, project_id: str) -> list[PackageVersionItem]:
        return list(self._package_versions_by_project.get(project_id, []))

    def persist_advisories(
        self,
        vulnerabilities: list[VulnerabilityRecord],
        links: list[AdvisoryLinkRecord],
    ) -> tuple[int, int, int, int]:
        advisories_created = 0
        advisories_updated = 0
        for v in vulnerabilities:
            if v.id in self._vulnerabilities:
                advisories_updated += 1
            else:
                advisories_created += 1
            self._vulnerabilities[v.id] = v

        links_created = 0
        links_reused = 0
        for l in links:
            pair = (l.package_version_id, l.advisory_id)
            if pair in self._links:
                links_reused += 1
            else:
                links_created += 1
                self._links.add(pair)
                self._link_records.append(l)

        return advisories_created, advisories_updated, links_created, links_reused

    def get_project_advisories(self, project_id: str) -> list[dict[str, Any]]:
        project_packages = {p.id: p for p in self.get_project_package_versions(project_id)}
        results: list[dict[str, Any]] = []

        for l in self._link_records:
            if l.package_version_id in project_packages and l.advisory_id in self._vulnerabilities:
                pkg = project_packages[l.package_version_id]
                vuln = self._vulnerabilities[l.advisory_id]
                results.append(
                    {
                        "id": vuln.id,
                        "summary": vuln.summary,
                        "details": vuln.details,
                        "severity": vuln.severity,
                        "cvss": vuln.cvss,
                        "aliases": list(vuln.aliases),
                        "published": vuln.published,
                        "modified": vuln.modified,
                        "source_url": vuln.source_url,
                        "retrieved_at": vuln.retrieved_at,
                        "package_version_id": pkg.id,
                        "package_name": pkg.name,
                        "package_version": pkg.version,
                        "ecosystem": pkg.ecosystem,
                    }
                )
        return results

    def clear(self) -> None:
        self._package_versions_by_project.clear()
        self._vulnerabilities.clear()
        self._links.clear()
        self._link_records.clear()


def get_advisory_repository() -> IAdvisoryRepository:
    return FalkorAdvisoryRepository()
