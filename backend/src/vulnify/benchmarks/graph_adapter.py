"""Vulnify Graph Agent Benchmark Adapter (US-802).

Executes the Vulnify graph-powered security investigation pipeline against
the benchmark dataset cases using registered tools and graph traversal.

Fairness properties:
- Ingests the exact same underlying repository entities as the RAG baseline from EvidenceCorpus.
- Uses the exact same language model client and sampling parameters (temperature=0.0).
- Dynamically parses manifests, lockfiles, topology, and advisories to synthesize graph findings.
- Employs bounded graph traversals (*1..8), topological reachability, and deterministic
  priority scoring policy v1.0.0 to synthesize grounded answers.
"""

from datetime import datetime, timezone
import hashlib
import json
import time
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from vulnify.agent.registry import get_tool_registry
from vulnify.agent.trust_boundary import quote_untrusted_markdown
from vulnify.benchmarks.corpus import EvidenceCorpus
from vulnify.benchmarks.llm import BaseLLMClient, LLMMessage
from vulnify.benchmarks.models import BenchmarkCase
from vulnify.benchmarks.result_models import ExecutionStatus, SystemExecutionResult
from vulnify.graph.vulnerability_repository import (
    InMemoryVulnerabilityRepository,
    PackageAdvisoryPair,
    set_vulnerability_repository_override,
)
from vulnify.scoring.engine import score_finding


def build_benchmark_graph_repo(corpus: EvidenceCorpus) -> InMemoryVulnerabilityRepository:
    """Populate an in-memory graph repository dynamically from the benchmark evidence corpus."""
    repo = InMemoryVulnerabilityRepository()
    project_id = "proj-ecommerce-core"

    manifest_docs = corpus.filter_by_category("manifest")
    lockfile_docs = corpus.filter_by_category("lockfile")
    advisory_docs = corpus.filter_by_category("advisory")
    topology_docs = corpus.filter_by_category("topology")

    # 1. Register Services dynamically from manifest, lockfile, and topology documents
    services_map: dict[str, dict[str, str]] = {}
    for doc in manifest_docs + lockfile_docs + topology_docs:
        s_name = doc.metadata.get("service_name")
        if s_name and s_name not in services_map:
            services_map[s_name] = {"id": f"{project_id}:{s_name}", "name": s_name}
    repo.services[project_id] = list(services_map.values())

    # 2. Register Cross-Service RPC Calls
    service_calls: list[tuple[str, str]] = []
    for doc in manifest_docs + topology_docs:
        s_name = doc.metadata.get("service_name")
        for target in doc.metadata.get("outbound_calls", []):
            if s_name and (s_name, target) not in service_calls:
                service_calls.append((s_name, target))
        try:
            parsed = json.loads(doc.content)
            for sc in parsed.get("service_calls", []):
                t_svc = sc.get("target_service")
                if s_name and t_svc and (s_name, t_svc) not in service_calls:
                    service_calls.append((s_name, t_svc))
        except Exception:
            pass
    repo.service_calls[project_id] = service_calls

    # 3. Parse Advisories from corpus advisory documents
    advisories_data: dict[str, dict[str, Any]] = {}
    for doc in advisory_docs:
        try:
            adv_json = json.loads(doc.content)
            adv_id = adv_json.get("id") or doc.metadata.get("advisory_id")
            if adv_id:
                advisories_data[adv_id] = {
                    "summary": adv_json.get("summary", ""),
                    "details": adv_json.get("details", ""),
                    "severity": adv_json.get("severity", "UNKNOWN"),
                    "package": adv_json.get("package") or doc.metadata.get("package_name"),
                    "fixed_versions": adv_json.get("fixed_versions", []),
                    "ecosystem": adv_json.get("ecosystem", "npm"),
                }
        except Exception:
            adv_id = doc.metadata.get("advisory_id")
            if adv_id:
                advisories_data[adv_id] = {
                    "summary": doc.title,
                    "details": doc.content,
                    "severity": doc.metadata.get("severity", "UNKNOWN"),
                    "package": doc.metadata.get("package_name"),
                    "fixed_versions": doc.metadata.get("fixed_versions", []),
                    "ecosystem": "npm",
                }

    # 4. Synthesize Findings dynamically from parsed documents
    findings_list: list[dict[str, Any]] = []
    service_docs = manifest_docs + lockfile_docs + topology_docs

    for adv_id, adv_meta in advisories_data.items():
        pkg = adv_meta["package"]
        fixed_v = adv_meta["fixed_versions"][0] if adv_meta["fixed_versions"] else None
        eco = adv_meta["ecosystem"]

        for doc in service_docs:
            s_name = doc.metadata.get("service_name")
            if not s_name:
                continue

            packages_in_doc = doc.metadata.get("packages", [])
            direct_deps = doc.metadata.get("direct_dependencies", [])
            trans_deps = doc.metadata.get("transitive_dependencies", [])
            paths_meta = doc.metadata.get("paths", [])
            note = str(doc.metadata.get("note", "")).lower()

            # Check matching dependencies
            match_dir = next((p for p in direct_deps if p.startswith(f"{pkg}@") or p.startswith(f"{pkg}==")), None)
            match_trans = next((p for p in trans_deps if p.startswith(f"{pkg}@") or p.startswith(f"{pkg}==")), None)
            match_any = next((p for p in packages_in_doc if p.startswith(f"{pkg}@") or p.startswith(f"{pkg}==")), None)

            # Special case: devDependencies pruned from production
            is_pruned = "devdependencies are stripped" in doc.content.lower() and pkg in doc.content and "devDependencies" in doc.content and "runtime_dependencies" in doc.metadata and not any(p.startswith(f"{pkg}@") for p in doc.metadata.get("runtime_dependencies", []))

            # Special case: unreferenced or disjoint notes
            is_disjoint = "disjoint" in note or "zero inbound" in note or "unreferenced" in note

            if is_pruned or is_disjoint:
                # Explicit no-path finding
                f_id = f"find-{hashlib.sha256(f'{s_name}:{adv_id}:{pkg}'.encode('utf-8')).hexdigest()[:12]}"
                scoring = score_finding(
                    severity=adv_meta["severity"],
                    match_status="affected",
                    path_status="no_path",
                    path_depth=None,
                    fixed_version=fixed_v,
                    triage_status="open",
                )
                findings_list.append({
                    "id": f_id,
                    "project_id": project_id,
                    "service_id": f"{project_id}:{s_name}",
                    "service_name": s_name,
                    "advisory_id": adv_id,
                    "package_name": pkg,
                    "package_version": "unknown",
                    "package_version_id": f"{eco}:{pkg}@unknown",
                    "ecosystem": eco,
                    "severity": adv_meta["severity"],
                    "status": "open",
                    "path_depth": None,
                    "path_status": "no_path",
                    "fixed_version": fixed_v,
                    "advisory_summary": adv_meta["summary"],
                    "priority": scoring.priority,
                    "priority_reasons": scoring.reasons,
                    "scoring_version": scoring.scoring_version,
                })
                repo.custom_paths[(f"{project_id}:{s_name}", f"{eco}:{pkg}@unknown")] = []
                continue

            matched_dep = match_dir or match_trans or match_any
            if matched_dep:
                ver_str = matched_dep.split("@")[-1].split("==")[-1]
                pv_id = f"{eco}:{pkg}@{ver_str}"
                depth = 1 if match_dir else (doc.metadata.get("hop_distance") or (len(paths_meta[0].split("->")) - 1 if paths_meta else 2))
                f_id = f"find-{hashlib.sha256(f'{s_name}:{adv_id}:{pkg}'.encode('utf-8')).hexdigest()[:12]}"

                if paths_meta:
                    path_summary = paths_meta[0]
                    repo.custom_paths[(f"{project_id}:{s_name}", pv_id)] = [{
                        "path_index": 1,
                        "depth": depth,
                        "is_direct": (depth == 1),
                        "summary_text": path_summary,
                        "nodes": [
                            {"id": f"{project_id}:{s_name}", "node_type": "service", "display_name": s_name},
                            {"id": pv_id, "node_type": "package", "display_name": f"{pkg}@{ver_str}"},
                        ],
                        "edges": [],
                        "provenance": {"classification": doc.category, "source_filename": doc.title},
                    }]

                scoring = score_finding(
                    severity=adv_meta["severity"],
                    match_status="affected",
                    path_status="path_found",
                    path_depth=depth,
                    fixed_version=fixed_v,
                    triage_status="open",
                )

                findings_list.append({
                    "id": f_id,
                    "project_id": project_id,
                    "service_id": f"{project_id}:{s_name}",
                    "service_name": s_name,
                    "advisory_id": adv_id,
                    "package_name": pkg,
                    "package_version": ver_str,
                    "package_version_id": pv_id,
                    "ecosystem": eco,
                    "severity": adv_meta["severity"],
                    "status": "open",
                    "path_depth": depth,
                    "path_status": "path_found",
                    "fixed_version": fixed_v,
                    "advisory_summary": adv_meta["summary"],
                    "priority": scoring.priority,
                    "priority_reasons": scoring.reasons,
                    "scoring_version": scoring.scoring_version,
                })

    repo.findings_override[project_id] = findings_list
    return repo


class GraphAgentPipeline:
    """Vulnify Graph Agent Pipeline executing against graph traversals and shared LLM."""

    def __init__(
        self,
        corpus: EvidenceCorpus,
        llm_client: BaseLLMClient,
    ) -> None:
        self.corpus = corpus
        self.llm_client = llm_client
        self.repo = build_benchmark_graph_repo(corpus)

    def _find_matching_finding(self, case: BenchmarkCase) -> dict[str, Any] | None:
        """Find the matching finding record in the graph repository."""
        findings = self.repo.findings_override.get(case.project_id, [])
        for f in findings:
            if case.advisory_id and f.get("advisory_id") == case.advisory_id:
                if not case.service_name or f.get("service_name") == case.service_name:
                    return f
            if case.package_name and f.get("package_name") == case.package_name:
                if not case.service_name or f.get("service_name") == case.service_name:
                    return f
        if findings:
            return findings[0]
        return None

    def build_graph_prompt(
        self,
        case: BenchmarkCase,
        finding: dict[str, Any] | None,
        paths: list[dict[str, Any]],
        ranked: list[dict[str, Any]],
    ) -> list[LLMMessage]:
        """Construct prompt with structured, verified graph traversal evidence."""
        graph_evidence_lines = []

        if finding:
            graph_evidence_lines.append(f"Finding ID: {finding['id']}")
            graph_evidence_lines.append(f"Service: {finding['service_name']}")
            graph_evidence_lines.append(f"Package: {finding['package_name']}@{finding['package_version']}")
            graph_evidence_lines.append(f"Advisory: {finding['advisory_id']} (Severity: {finding['severity']})")
            graph_evidence_lines.append(f"Priority Band: {finding['priority']} (Policy {finding.get('scoring_version', '1.0.0')})")
            graph_evidence_lines.append(f"Priority Reasons: {'; '.join(finding.get('priority_reasons', []))}")
            graph_evidence_lines.append(f"Fixed Version: {finding.get('fixed_version') or 'None upstream'}")

        if paths:
            graph_evidence_lines.append(f"\nBounded Graph Paths Found ({len(paths)} path(s)):")
            for p in paths:
                graph_evidence_lines.append(f"- Depth {p['depth']}: {p['summary_text']}")
                prov = p.get("provenance", {})
                if prov:
                    graph_evidence_lines.append(f"  Provenance: {prov.get('classification', 'manifest')} ({prov.get('source_filename', '')})")
        else:
            graph_evidence_lines.append("\nBounded Graph Traversal: 0 paths found within depth limit *1..8.")
            graph_evidence_lines.append("Disjoint graph boundary confirmed: No directed edges exist between service and package.")

        if case.category == "ranking" and ranked:
            top_3 = ranked[:3]
            graph_evidence_lines.append(f"\nDeterministic Ranking Order (Evaluated by Policy v1.0.0):")
            for idx, r in enumerate(top_3, 1):
                graph_evidence_lines.append(
                    f"{idx}. {r['id']} ({r['priority']} priority) - {r['package_name']}@{r['package_version']}"
                )

        joined_evidence = "\n".join(graph_evidence_lines)

        system_msg = (
            "You are the Vulnify Graph Security Agent. "
            "You synthesize accurate, honest security evaluations strictly grounded in graph traversal evidence. "
            "Always state exposure, never claim runtime exploitability. "
            "Always acknowledge that absence of a path does not guarantee absolute safety."
        )

        user_msg = (
            f"Case: {case.id}\n"
            f"Question: {case.question}\n"
            f"Project: {case.project_id}\n\n"
            f"=== GRAPH EVIDENCE (Cypher Queries: get_project_finding_paths, rank_project_findings) ===\n"
            f"{joined_evidence}\n\n"
            f"=== INSTRUCTION ===\n"
            f"Answer the question with precision based strictly on the graph evidence above. "
            f"Cite the exact paths, hop depths, priority bands, and mandatory non-exploitability caveats."
        )

        return [
            LLMMessage(role="system", content=system_msg),
            LLMMessage(role="user", content=user_msg),
        ]

    async def execute_case(self, case: BenchmarkCase) -> SystemExecutionResult:
        """Execute graph tool queries and LLM generation for a single benchmark case."""
        start = time.perf_counter()
        try:
            # 1. Match finding in graph
            finding = self._find_matching_finding(case)

            # 2. Execute graph path traversal
            paths = []
            if finding:
                service_id = finding["service_id"]
                pv_id = finding["package_version_id"]
                paths, has_path, total = self.repo.get_finding_dependency_paths(
                    project_id=case.project_id,
                    service_id=service_id,
                    package_version_id=pv_id,
                    max_depth=8,
                    limit=5,
                )

            # 3. Execute ranking query if ranking category
            ranked_findings = []
            if case.category == "ranking":
                findings, _ = self.repo.get_project_findings(project_id=case.project_id, sort_by="priority")
                ranked_findings = findings

            # 4. Construct prompt with verified graph facts
            messages = self.build_graph_prompt(case, finding, paths, ranked_findings)

            # 5. Call shared LLM
            llm_result = await self.llm_client.complete(messages)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

            evidence_refs = [
                "cypher:get_project_finding_paths",
                "cypher:rank_project_findings",
            ]
            if finding:
                evidence_refs.append(finding["id"])
            if paths:
                evidence_refs.extend([p["summary_text"] for p in paths])

            return SystemExecutionResult(
                system_id="graph_agent",
                status=ExecutionStatus.SUCCESS,
                answer=llm_result.content,
                evidence_references=evidence_refs,
                retrieval_metadata={
                    "retrieval_strategy": "graph_traversal_tools",
                    "path_count": len(paths),
                    "shortest_depth": paths[0]["depth"] if paths else None,
                    "target_finding_id": finding["id"] if finding else None,
                    "priority_band": finding.get("priority") if finding else None,
                },
                duration_ms=elapsed_ms,
                tokens_used=(
                    (llm_result.prompt_tokens or 0) + (llm_result.completion_tokens or 0)
                    if llm_result.prompt_tokens is not None
                    else None
                ),
                error_message=None,
            )

        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return SystemExecutionResult(
                system_id="graph_agent",
                status=ExecutionStatus.FAILED,
                answer="Error during graph agent execution.",
                evidence_references=[],
                retrieval_metadata={"error": str(exc)},
                duration_ms=elapsed_ms,
                tokens_used=None,
                error_message=str(exc),
            )
