"""Upgrade Candidates evaluation service (US-401 / US-501).

Implements deterministic, evidence-grounded candidate upgrade evaluation:
1. Candidates come strictly from advisory's verified fixed versions.
2. Labelled 'recommended', 'major version' or 'patch only'.
3. Shows contextual compatibility caveats (breaking change risk, transitive parent notes, manifest ranges).
4. Honest 'no fix available' state when no fixed version exists.
5. Explicit disclaimers: never claims an upgrade is safe to ship.
"""

from datetime import datetime, timezone
import logging
import re
from typing import Any
from fastapi import Depends

from vulnify.graph.vulnerability_repository import (
    IVulnerabilityRepository,
    get_vulnerability_repository,
)
from vulnify.schemas import (
    CandidateClassificationLiteral,
    CandidateFixStatusLiteral,
    CompatibilityStatusLiteral,
    BreakingChangeRiskLiteral,
    ProjectUpgradeCandidatesResponse,
    UpgradeCandidateItem,
    UpgradeCandidatesResponse,
)
from vulnify.version_matching.comparators.base import (
    InvalidVersionError,
    UnsupportedEcosystemError,
)
from vulnify.version_matching.comparators.registry import get_comparator

logger = logging.getLogger("vulnify")

MANDATORY_SAFETY_DISCLAIMER = (
    "No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that "
    "the security advisory reports the vulnerability as resolved in that release. "
    "Upgrades may introduce regressions, breaking changes, or undeclared side effects. "
    "Always run test suites and security validation before deploying to production."
)

NO_FIX_MESSAGE = (
    "No fixed version published in advisory. No verified remediation target available. "
    "Consider workarounds, isolating the affected service, or replacing the dependency."
)

NO_FIX_GUIDANCE = (
    "Because the upstream vendor or advisory authority has not published a patched release, "
    "automated dependency upgrades cannot resolve this vulnerability. We recommend: "
    "1. Inspecting advisory references for defensive workarounds or configuration mitigations. "
    "2. Isolating or segmenting the affected service from untrusted input. "
    "3. Replacing the dependency with an actively maintained alternative if no fix is forthcoming."
)


def parse_version_tuple(version_str: str, ecosystem: str = "npm") -> tuple[int, int, int] | None:
    """Parse a version string into (major, minor, patch) components adhering to ecosystem grammar."""
    if not version_str or not isinstance(version_str, str):
        return None
    cleaned = version_str.strip().lstrip("v").lstrip("=").strip()

    # Try ecosystem comparator if supported
    try:
        comparator = get_comparator(ecosystem)
        parsed = comparator.parse(cleaned)
        if hasattr(parsed, "major"):
            major = int(parsed.major)
            minor = int(getattr(parsed, "minor", 0))
            patch = int(getattr(parsed, "patch", getattr(parsed, "micro", 0)))
            return (major, minor, patch)
        if hasattr(parsed, "release") and parsed.release:
            rel = parsed.release
            major = int(rel[0])
            minor = int(rel[1]) if len(rel) > 1 else 0
            patch = int(rel[2]) if len(rel) > 2 else 0
            return (major, minor, patch)
    except (InvalidVersionError, UnsupportedEcosystemError, Exception):
        pass

    # Generic fallback using regex for semver-like strings
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", cleaned)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2)) if match.group(2) is not None else 0
        patch = int(match.group(3)) if match.group(3) is not None else 0
        return (major, minor, patch)

    return None


def compare_versions(v1: str, v2: str, ecosystem: str = "npm") -> int:
    """Compare two version strings. Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2."""
    try:
        comp = get_comparator(ecosystem)
        return comp.compare(v1, v2)
    except Exception:
        t1 = parse_version_tuple(v1, ecosystem)
        t2 = parse_version_tuple(v2, ecosystem)
        if t1 is not None and t2 is not None:
            if t1 < t2:
                return -1
            if t1 > t2:
                return 1
            return 0
        if v1 < v2:
            return -1
        if v1 > v2:
            return 1
        return 0


def evaluate_upgrade_candidates_for_finding(
    project_id: str,
    finding: dict[str, Any],
) -> UpgradeCandidatesResponse:
    """Evaluate candidate upgrade targets for an individual confirmed finding."""
    now = int(datetime.now(timezone.utc).timestamp())

    finding_id = str(finding.get("id") or "")
    advisory_id = str(finding.get("advisory_id") or "")
    package_name = str(finding.get("package_name") or "")
    current_version = str(finding.get("package_version") or "")
    ecosystem = str(finding.get("ecosystem") or "npm")
    service_id = str(finding.get("service_id") or "")
    service_name = str(finding.get("service_name") or "")
    raw_depth = finding.get("path_depth")
    path_depth = int(raw_depth) if raw_depth is not None else None
    is_transitive = path_depth is not None and path_depth > 1

    # 1. Collect all known fixed versions from graph evidence
    raw_fixed_versions: list[str] = []

    # From advisory_fixed_versions list
    adv_fixed = finding.get("advisory_fixed_versions")
    if isinstance(adv_fixed, (list, tuple)):
        for fv in adv_fixed:
            if fv and str(fv).strip() and str(fv).strip() != "0":
                raw_fixed_versions.append(str(fv).strip())

    # From fixed_version string (single earliest or primary)
    single_fixed = finding.get("fixed_version")
    if single_fixed and str(single_fixed).strip() and str(single_fixed).strip() != "0":
        clean_single = str(single_fixed).strip()
        if clean_single not in raw_fixed_versions:
            raw_fixed_versions.append(clean_single)

    # Deduplicate while preserving order
    distinct_fixed: list[str] = []
    for fv in raw_fixed_versions:
        if fv not in distinct_fixed:
            distinct_fixed.append(fv)

    # 2. AC-3: If no fixed version exists, return explicit 'no fix available' state
    if not distinct_fixed:
        return UpgradeCandidatesResponse(
            project_id=project_id,
            finding_id=finding_id,
            advisory_id=advisory_id,
            package_name=package_name,
            current_version=current_version,
            ecosystem=ecosystem,
            service_id=service_id,
            service_name=service_name,
            path_depth=path_depth,
            is_transitive=is_transitive,
            has_fix=False,
            candidates=[],
            no_fix_message=NO_FIX_MESSAGE,
            remediation_guidance=NO_FIX_GUIDANCE,
            safety_disclaimer=MANDATORY_SAFETY_DISCLAIMER,
            evaluated_at=now,
        )

    # 3. Sort candidate versions in ascending order
    def _sort_key(ver: str) -> tuple[int, int, int, str]:
        t = parse_version_tuple(ver, ecosystem)
        if t:
            return (t[0], t[1], t[2], ver)
        return (9999, 9999, 9999, ver)

    sorted_fixed = sorted(distinct_fixed, key=_sort_key)

    # Filter to versions that are forward upgrades (greater than current_version),
    # or fallback to all fixed versions if comparison cannot prove order.
    forward_fixed: list[str] = []
    for ver in sorted_fixed:
        if current_version:
            cmp_res = compare_versions(ver, current_version, ecosystem)
            if cmp_res > 0:
                forward_fixed.append(ver)
        else:
            forward_fixed.append(ver)

    if not forward_fixed:
        # If all fixed versions appear <= current, provide the sorted fixed versions anyway
        forward_fixed = sorted_fixed

    # 4. Evaluate each candidate version: semver_diff, caveats, breaking risk
    curr_tup = parse_version_tuple(current_version, ecosystem)

    raw_candidates: list[UpgradeCandidateItem] = []
    for target_ver in forward_fixed:
        target_tup = parse_version_tuple(target_ver, ecosystem)

        semver_diff = "unknown"
        breaking_risk: BreakingChangeRiskLiteral = "unknown"
        candidate_label = "Recommended"
        caveats: list[str] = []

        if curr_tup and target_tup:
            c_maj, c_min, c_pat = curr_tup
            t_maj, t_min, t_pat = target_tup

            if t_maj > c_maj:
                semver_diff = "major"
                breaking_risk = "high"
                candidate_label = "Major version"
                caveats.append(
                    f"Major version upgrade (v{c_maj} -> v{t_maj}): High probability of breaking API changes, "
                    "configuration differences, or deprecated feature removals. Review changelogs and migration guides thoroughly."
                )
            elif t_maj == c_maj and t_min == c_min and t_pat > c_pat:
                semver_diff = "patch"
                breaking_risk = "low"
                candidate_label = "Patch only"
                caveats.append(
                    f"Patch-only upgrade (v{c_maj}.{c_min}.{c_pat} -> v{t_maj}.{t_min}.{t_pat}): "
                    "Backwards-compatible bug and security fix. Minimal regression risk within the same release series."
                )
            elif t_maj == c_maj and t_min > c_min:
                semver_diff = "minor"
                breaking_risk = "low"
                candidate_label = "Minor version"
                caveats.append(
                    f"Minor version upgrade (v{c_maj}.{c_min} -> v{t_maj}.{t_min}): "
                    "Backward-compatible feature and fix release under SemVer rules. Low regression risk, but verify dependency interactions."
                )
            else:
                semver_diff = "unknown"
                breaking_risk = "unknown"
                candidate_label = "Target version"
        else:
            semver_diff = "unknown"
            breaking_risk = "unknown"
            candidate_label = "Target version"
            caveats.append(
                f"Version string '{target_ver}' does not strictly follow standard numeric SemVer rules; automated compatibility inference is limited."
            )

        # Transitive vs Direct dependency caveat
        if is_transitive:
            caveats.append(
                f"Transitive dependency (depth: {path_depth} hops): Package '{package_name}' is brought in by parent dependencies. "
                "Direct manifest upgrade may require bumping parent packages or using package manager overrides (e.g. npm 'overrides', yarn 'resolutions', or pip constraints)."
            )
        else:
            caveats.append(
                f"Direct dependency: Check declared manifest constraints in lockfile/manifest to ensure target version '{target_ver}' is allowed by range specifiers."
            )

        # AC-2: Tool NEVER claims an upgrade is safe to ship
        caveats.append(
            "Absence of detected conflicts does not guarantee runtime compatibility or application safety. "
            "Vulnify never claims an upgrade is safe to ship without project-level integration and regression testing."
        )

        labels_list = [candidate_label.lower()]

        raw_candidates.append(
            UpgradeCandidateItem(
                target_version=target_ver,
                classification="patch" if semver_diff == "patch" else ("major" if semver_diff == "major" else "minor" if semver_diff == "minor" else "unknown"),
                label=candidate_label,
                labels=labels_list,
                semver_diff=semver_diff,
                is_recommended=False,
                fix_status="fix_supported",
                compatibility_status="conflict" if breaking_risk == "high" else ("compatible" if breaking_risk == "low" else "unknown"),
                breaking_change_risk=breaking_risk,
                caveats=caveats,
                evidence_source="Advisory fixed version declaration",
            )
        )

    # 5. AC-1: Select the primary recommended candidate
    # Preference:
    # 1st: patch-only fix in current major line
    # 2nd: minor fix in current major line
    # 3rd: earliest major fix
    recommended_idx = 0
    patch_indices = [i for i, c in enumerate(raw_candidates) if c.semver_diff == "patch"]
    minor_indices = [i for i, c in enumerate(raw_candidates) if c.semver_diff == "minor"]

    if patch_indices:
        recommended_idx = patch_indices[0]
    elif minor_indices:
        recommended_idx = minor_indices[0]
    else:
        recommended_idx = 0

    final_candidates: list[UpgradeCandidateItem] = []
    for idx, cand in enumerate(raw_candidates):
        is_rec = (idx == recommended_idx)
        labels = list(cand.labels)
        if is_rec and "recommended" not in labels:
            labels.insert(0, "recommended")

        primary_class: CandidateClassificationLiteral = "recommended" if is_rec else cand.classification
        primary_label = "Recommended" if is_rec else cand.label

        final_candidates.append(
            cand.model_copy(
                update={
                    "is_recommended": is_rec,
                    "classification": primary_class,
                    "label": primary_label,
                    "labels": labels,
                }
            )
        )

    return UpgradeCandidatesResponse(
        project_id=project_id,
        finding_id=finding_id,
        advisory_id=advisory_id,
        package_name=package_name,
        current_version=current_version,
        ecosystem=ecosystem,
        service_id=service_id,
        service_name=service_name,
        path_depth=path_depth,
        is_transitive=is_transitive,
        has_fix=True,
        candidates=final_candidates,
        no_fix_message=None,
        remediation_guidance=(
            "Review candidate SemVer diffs, check for breaking API changes, and test before applying. "
            "Never deploy upgrades directly to production without running test suites."
        ),
        safety_disclaimer=MANDATORY_SAFETY_DISCLAIMER,
        evaluated_at=now,
    )


class UpgradeCandidatesService:
    """Service orchestrating upgrade candidate evaluation for project findings."""

    def __init__(self, repo: IVulnerabilityRepository | None = None) -> None:
        self.repo = repo or get_vulnerability_repository()

    def get_finding_upgrade_candidates(
        self,
        project_id: str,
        finding_id: str,
    ) -> UpgradeCandidatesResponse | None:
        finding = self.repo.get_project_finding_detail(project_id, finding_id)
        if not finding:
            return None
        return evaluate_upgrade_candidates_for_finding(project_id, finding)

    def get_project_upgrade_candidates(
        self,
        project_id: str,
    ) -> ProjectUpgradeCandidatesResponse:
        now = int(datetime.now(timezone.utc).timestamp())
        findings, _ = self.repo.get_project_findings(project_id=project_id, limit=500)

        items: list[UpgradeCandidatesResponse] = []
        with_fix = 0
        without_fix = 0

        for f in findings:
            finding_detail = self.repo.get_project_finding_detail(project_id, f["id"]) or f
            res = evaluate_upgrade_candidates_for_finding(project_id, finding_detail)
            items.append(res)
            if res.has_fix:
                with_fix += 1
            else:
                without_fix += 1

        return ProjectUpgradeCandidatesResponse(
            project_id=project_id,
            total_findings=len(items),
            findings_with_fix=with_fix,
            findings_without_fix=without_fix,
            items=items,
            safety_disclaimer=MANDATORY_SAFETY_DISCLAIMER,
            evaluated_at=now,
        )


_upgrade_candidates_service: UpgradeCandidatesService | None = None


def get_upgrade_candidates_service(
    repo: IVulnerabilityRepository = Depends(get_vulnerability_repository),
) -> UpgradeCandidatesService:
    return UpgradeCandidatesService(repo=repo)
