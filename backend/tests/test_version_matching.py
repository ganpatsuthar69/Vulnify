"""Comprehensive test suite for US-104: Ecosystem-aware Version Matching.

Covers:
- Category A: Basic version semantics (inside, before, after, boundaries, multi-part, lexical vs semantic)
- Category B: Pre-releases and ecosystem-specific behavior (npm SemVer vs PyPI PEP 440, invalid strings)
- Category C: OSV range events (introduced, fixed, last_affected, limit, open-ended, multiple ranges/packages, malformed/unsupported)
- Category D: Persistence, idempotency, re-evaluation, project scoping, unknown handling
- Category E: Real advisory verification (npm lodash GHSA-29mw-wpgm-hmr9, PyPI requests GHSA-652x-xj99-gmcc)
- API endpoint integration
"""

import json
import uuid
from httpx import AsyncClient
import pytest

from vulnify.dependencies import COOKIE_SESSION_NAME
from vulnify.graph.advisory_repository import InMemoryAdvisoryRepository, PackageVersionItem
from vulnify.graph.project_repository import InMemoryProjectRepository
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.graph.vulnerability_repository import (
    InMemoryVulnerabilityRepository,
    PackageAdvisoryPair,
)
from vulnify.security import create_session_jwt
from vulnify.version_matching.comparators.base import InvalidVersionError, UnsupportedEcosystemError
from vulnify.version_matching.comparators.npm import NpmVersionComparator
from vulnify.version_matching.comparators.pypi import PyPIVersionComparator
from vulnify.version_matching.comparators.registry import get_comparator, get_range_comparator
from vulnify.version_matching.models import (
    AdvisoryData,
    MatchReasonCode,
    MatchStatus,
    OSVAffectedPackage,
    OSVRange,
    OSVRangeEvent,
    VersionMatchResult,
)
from vulnify.version_matching.range_evaluator import evaluate_version_against_advisory
from vulnify.version_matching.service import VersionMatchingService


# ==============================================================================
# Category A: Basic Version Semantics & Lexical vs Semantic Comparison
# ==============================================================================


def test_lexical_vs_semantic_ordering() -> None:
    """Proves that version comparison uses ecosystem semantics, NOT lexical string comparison.
    
    Lexically: "1.10.0" < "1.2.0" because '1' < '2' at character index 2.
    Semantically: 1.10.0 > 1.2.0 because minor component 10 > 2.
    """
    npm_comp = NpmVersionComparator()
    pypi_comp = PyPIVersionComparator()

    # Plain string comparison gives misleading result:
    assert "1.10.0" < "1.2.0"

    # Ecosystem-aware semantic comparison gives true result:
    assert npm_comp.compare("1.10.0", "1.2.0") > 0
    assert pypi_comp.compare("1.10.0", "1.2.0") > 0


def test_category_a_inside_affected_range() -> None:
    """A version strictly inside an introduced..fixed affected range is AFFECTED."""
    adv = AdvisoryData(
        id="OSV-TEST-001",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="1.0.0"),
                            OSVRangeEvent(fixed="2.0.0"),
                        ],
                    )
                ],
            )
        ],
    )
    res = evaluate_version_against_advisory("test-lib", "1.5.0", "npm", adv)
    assert res.status == MatchStatus.AFFECTED
    assert res.reason_code == MatchReasonCode.WITHIN_AFFECTED_RANGE
    assert res.fixed_version == "2.0.0"
    assert res.matched_range == ">= 1.0.0, < 2.0.0"


def test_category_a_before_affected_range() -> None:
    """A version strictly before the introduced version is NOT_AFFECTED."""
    adv = AdvisoryData(
        id="OSV-TEST-002",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="2.0.0"),
                            OSVRangeEvent(fixed="3.0.0"),
                        ],
                    )
                ],
            )
        ],
    )
    res = evaluate_version_against_advisory("test-lib", "1.9.9", "npm", adv)
    assert res.status == MatchStatus.NOT_AFFECTED
    assert res.reason_code == MatchReasonCode.BEFORE_INTRODUCED_VERSION
    assert "before introduced version 2.0.0" in res.reason


def test_category_a_after_affected_range_at_or_above_fixed() -> None:
    """A version at or above the fixed version is NOT_AFFECTED."""
    adv = AdvisoryData(
        id="OSV-TEST-003",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="1.0.0"),
                            OSVRangeEvent(fixed="2.0.0"),
                        ],
                    )
                ],
            )
        ],
    )
    # Exactly fixed version (exclusive upper bound)
    res_fixed = evaluate_version_against_advisory("test-lib", "2.0.0", "npm", adv)
    assert res_fixed.status == MatchStatus.NOT_AFFECTED
    assert res_fixed.reason_code == MatchReasonCode.AT_OR_ABOVE_FIXED_VERSION
    assert res_fixed.fixed_version == "2.0.0"

    # Beyond fixed version
    res_after = evaluate_version_against_advisory("test-lib", "2.1.0", "npm", adv)
    assert res_after.status == MatchStatus.NOT_AFFECTED
    assert res_after.reason_code == MatchReasonCode.AT_OR_ABOVE_FIXED_VERSION


def test_category_a_exact_introduced_lower_bound() -> None:
    """The exact introduced version is inclusive and therefore AFFECTED."""
    adv = AdvisoryData(
        id="OSV-TEST-004",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="1.2.0"),
                            OSVRangeEvent(fixed="1.3.0"),
                        ],
                    )
                ],
            )
        ],
    )
    res = evaluate_version_against_advisory("test-lib", "1.2.0", "npm", adv)
    assert res.status == MatchStatus.AFFECTED
    assert res.reason_code == MatchReasonCode.WITHIN_AFFECTED_RANGE


def test_category_a_multi_numeric_components() -> None:
    """Multi-digit version components (e.g. 1.10.4 vs 1.2.9) compare correctly."""
    adv = AdvisoryData(
        id="OSV-TEST-005",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="1.2.0"),
                            OSVRangeEvent(fixed="1.10.0"),
                        ],
                    )
                ],
            )
        ],
    )
    # 1.9.5 is inside [1.2.0, 1.10.0)
    assert evaluate_version_against_advisory("test-lib", "1.9.5", "npm", adv).status == MatchStatus.AFFECTED
    # 1.10.1 is outside [1.2.0, 1.10.0)
    assert evaluate_version_against_advisory("test-lib", "1.10.1", "npm", adv).status == MatchStatus.NOT_AFFECTED


# ==============================================================================
# Category B: Pre-releases and Ecosystem-Specific Behavior
# ==============================================================================


def test_category_b_prerelease_behavior() -> None:
    """Pre-releases are ordered before their corresponding release under SemVer 2.0.0."""
    npm_comp = NpmVersionComparator()
    assert npm_comp.compare("1.0.0-alpha", "1.0.0") < 0
    assert npm_comp.compare("1.0.0-alpha.1", "1.0.0-alpha.2") < 0
    assert npm_comp.compare("1.0.0-beta", "1.0.0-alpha") > 0

    # In range < 2.0.0, 2.0.0-beta is < 2.0.0, so it is affected
    adv = AdvisoryData(
        id="OSV-TEST-006",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="0"),
                            OSVRangeEvent(fixed="2.0.0"),
                        ],
                    )
                ],
            )
        ],
    )
    res_pre = evaluate_version_against_advisory("test-lib", "2.0.0-beta.1", "npm", adv)
    assert res_pre.status == MatchStatus.AFFECTED

    res_rel = evaluate_version_against_advisory("test-lib", "2.0.0", "npm", adv)
    assert res_rel.status == MatchStatus.NOT_AFFECTED


def test_category_b_ecosystem_normalization() -> None:
    """Prefixes like 'v' and '=' are normalized in npm versions."""
    npm_comp = NpmVersionComparator()
    assert npm_comp.normalize("v1.2.3") == "1.2.3"
    assert npm_comp.normalize("=1.2.3") == "1.2.3"
    assert npm_comp.normalize("1.2") == "1.2.0"

    adv = AdvisoryData(
        id="OSV-TEST-007",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="0"),
                            OSVRangeEvent(fixed="1.5.0"),
                        ],
                    )
                ],
            )
        ],
    )
    res = evaluate_version_against_advisory("test-lib", "v1.2.3", "npm", adv)
    assert res.status == MatchStatus.AFFECTED


def test_category_b_invalid_version_string_yields_unknown() -> None:
    """Invalid version strings return UNKNOWN, never NOT_AFFECTED."""
    adv = AdvisoryData(
        id="OSV-TEST-008",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="0"),
                            OSVRangeEvent(fixed="2.0.0"),
                        ],
                    )
                ],
            )
        ],
    )
    res = evaluate_version_against_advisory("test-lib", "not-a-valid-version", "npm", adv)
    assert res.status == MatchStatus.UNKNOWN
    assert res.reason_code == MatchReasonCode.INVALID_VERSION
    assert "is invalid under npm rules" in res.reason


def test_category_b_version_valid_in_pypi_but_invalid_in_npm() -> None:
    """4-part versions like 1.2.3.4 are valid in PyPI (PEP 440) but invalid in npm (SemVer)."""
    pypi_comp = PyPIVersionComparator()
    npm_comp = NpmVersionComparator()

    assert pypi_comp.parse("1.2.3.4") is not None
    with pytest.raises(InvalidVersionError):
        npm_comp.parse("1.2.3.4")


def test_category_b_explicit_versions_list() -> None:
    """Matches against explicit versions lists in OSV affected entries."""
    adv = AdvisoryData(
        id="OSV-TEST-009",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[],
                versions=["1.0.1", "1.0.5", "1.2.0"],
            )
        ],
    )
    res_match = evaluate_version_against_advisory("test-lib", "1.0.5", "npm", adv)
    assert res_match.status == MatchStatus.AFFECTED
    assert res_match.reason_code == MatchReasonCode.EXPLICIT_VERSION_MATCH

    res_no_match = evaluate_version_against_advisory("test-lib", "1.0.2", "npm", adv)
    assert res_no_match.status == MatchStatus.NOT_AFFECTED
    assert res_no_match.reason_code == MatchReasonCode.OUTSIDE_AFFECTED_RANGES


# ==============================================================================
# Category C: OSV Range Events & Boundaries
# ==============================================================================


def test_category_c_last_affected_inclusive_boundary() -> None:
    """The last_affected event is inclusive, unlike fixed which is exclusive."""
    adv = AdvisoryData(
        id="OSV-TEST-010",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="1.0.0"),
                            OSVRangeEvent(last_affected="1.5.0"),
                        ],
                    )
                ],
            )
        ],
    )
    # Exactly last_affected version is inclusive -> AFFECTED
    res_last = evaluate_version_against_advisory("test-lib", "1.5.0", "npm", adv)
    assert res_last.status == MatchStatus.AFFECTED
    assert res_last.matched_range == ">= 1.0.0, <= 1.5.0"

    # Strictly greater is NOT_AFFECTED
    res_after = evaluate_version_against_advisory("test-lib", "1.5.1", "npm", adv)
    assert res_after.status == MatchStatus.NOT_AFFECTED


def test_category_c_limit_event() -> None:
    """The limit event establishes an upper bound that acts exclusively."""
    adv = AdvisoryData(
        id="OSV-TEST-011",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="1.0.0"),
                            OSVRangeEvent(limit="2.0.0"),
                        ],
                    )
                ],
            )
        ],
    )
    assert evaluate_version_against_advisory("test-lib", "1.9.9", "npm", adv).status == MatchStatus.AFFECTED
    assert evaluate_version_against_advisory("test-lib", "2.0.0", "npm", adv).status == MatchStatus.NOT_AFFECTED


def test_category_c_open_ended_range() -> None:
    """An introduced event without a fixed/last_affected event affects all subsequent versions."""
    adv = AdvisoryData(
        id="OSV-TEST-012",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="1.0.0"),
                        ],
                    )
                ],
            )
        ],
    )
    assert evaluate_version_against_advisory("test-lib", "99.0.0", "npm", adv).status == MatchStatus.AFFECTED
    assert evaluate_version_against_advisory("test-lib", "0.9.0", "npm", adv).status == MatchStatus.NOT_AFFECTED


def test_category_c_multiple_disjoint_ranges() -> None:
    """Handles multiple affected spans correctly (e.g. 1.x branch and 2.x branch)."""
    adv = AdvisoryData(
        id="OSV-TEST-013",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="1.0.0"),
                            OSVRangeEvent(fixed="1.2.0"),
                            OSVRangeEvent(introduced="2.0.0"),
                            OSVRangeEvent(fixed="2.1.0"),
                        ],
                    )
                ],
            )
        ],
    )
    # Inside span 1
    assert evaluate_version_against_advisory("test-lib", "1.1.0", "npm", adv).status == MatchStatus.AFFECTED
    # Fixed in span 1
    assert evaluate_version_against_advisory("test-lib", "1.2.0", "npm", adv).status == MatchStatus.NOT_AFFECTED
    # Between spans
    assert evaluate_version_against_advisory("test-lib", "1.5.0", "npm", adv).status == MatchStatus.NOT_AFFECTED
    # Inside span 2
    assert evaluate_version_against_advisory("test-lib", "2.0.5", "npm", adv).status == MatchStatus.AFFECTED
    # Fixed in span 2
    assert evaluate_version_against_advisory("test-lib", "2.1.0", "npm", adv).status == MatchStatus.NOT_AFFECTED


def test_category_c_multiple_affected_packages() -> None:
    """Advisories targeting multiple packages only match the package matching the name."""
    adv = AdvisoryData(
        id="OSV-TEST-014",
        affected=[
            OSVAffectedPackage(
                package_name="pkg-a",
                ecosystem="npm",
                ranges=[
                    OSVRange(type="SEMVER", events=[OSVRangeEvent(introduced="0"), OSVRangeEvent(fixed="1.0.0")])
                ],
            ),
            OSVAffectedPackage(
                package_name="pkg-b",
                ecosystem="npm",
                ranges=[
                    OSVRange(type="SEMVER", events=[OSVRangeEvent(introduced="0"), OSVRangeEvent(fixed="2.0.0")])
                ],
            ),
        ],
    )
    # pkg-a @ 1.5.0 is NOT affected (fixed in 1.0.0)
    assert evaluate_version_against_advisory("pkg-a", "1.5.0", "npm", adv).status == MatchStatus.NOT_AFFECTED
    # pkg-b @ 1.5.0 IS affected (fixed in 2.0.0)
    assert evaluate_version_against_advisory("pkg-b", "1.5.0", "npm", adv).status == MatchStatus.AFFECTED


def test_category_c_malformed_range_data_yields_unknown() -> None:
    """Malformed range data (e.g. empty events or unparseable range boundaries) yields UNKNOWN."""
    adv_empty_events = AdvisoryData(
        id="OSV-TEST-015",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[OSVRange(type="SEMVER", events=[])],
            )
        ],
    )
    res_empty = evaluate_version_against_advisory("test-lib", "1.0.0", "npm", adv_empty_events)
    assert res_empty.status == MatchStatus.UNKNOWN
    assert res_empty.reason_code == MatchReasonCode.MALFORMED_RANGE

    adv_bad_fixed = AdvisoryData(
        id="OSV-TEST-016",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVRangeEvent(introduced="1.0.0"),
                            OSVRangeEvent(fixed="not-a-version"),
                        ],
                    )
                ],
            )
        ],
    )
    res_bad = evaluate_version_against_advisory("test-lib", "1.5.0", "npm", adv_bad_fixed)
    assert res_bad.status == MatchStatus.UNKNOWN
    assert res_bad.reason_code == MatchReasonCode.MALFORMED_RANGE


def test_category_c_unsupported_range_type_git() -> None:
    """GIT commit ranges are unsupported for package version evaluation and yield UNKNOWN."""
    adv = AdvisoryData(
        id="OSV-TEST-017",
        affected=[
            OSVAffectedPackage(
                package_name="test-lib",
                ecosystem="npm",
                ranges=[
                    OSVRange(
                        type="GIT",
                        events=[
                            OSVRangeEvent(introduced="a1b2c3d"),
                            OSVRangeEvent(fixed="e4f5g6h"),
                        ],
                    )
                ],
            )
        ],
    )
    res = evaluate_version_against_advisory("test-lib", "1.0.0", "npm", adv)
    assert res.status == MatchStatus.UNKNOWN
    assert res.reason_code == MatchReasonCode.UNSUPPORTED_RANGE_TYPE


# ==============================================================================
# Category D: Persistence, Service Orchestration & Idempotency
# ==============================================================================


def test_category_d_persistence_and_idempotency() -> None:
    """Executing version matching creates AFFECTS relationships and repeated runs are idempotent."""
    repo = InMemoryVulnerabilityRepository()
    service = VersionMatchingService(repo=repo)
    project_id = "proj-123"

    # Set up package-advisory pair: lodash 4.17.20 with fixed: 4.17.21
    adv_payload = [
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                }
            ],
        }
    ]
    repo.package_advisories[project_id] = [
        PackageAdvisoryPair(
            package_version_id="pv-lodash-4.17.20",
            package_name="lodash",
            package_version="4.17.20",
            ecosystem="npm",
            vulnerability_id="GHSA-test-01",
            affected_ranges=json.dumps(adv_payload),
            fixed_versions=["4.17.21"],
            summary="Prototype Pollution in lodash",
            severity="HIGH",
        )
    ]

    # First run
    resp1 = service.match_project_vulnerabilities(project_id)
    assert resp1.total_evaluated == 1
    assert resp1.affected_count == 1
    assert resp1.relationships_persisted == 1
    assert len(repo.affects_edges) == 1

    edge = repo.affects_edges[("GHSA-test-01", "pv-lodash-4.17.20")]
    assert edge["status"] == "affected"
    assert edge["fixed_version"] == "4.17.21"
    assert edge["reason_code"] == MatchReasonCode.WITHIN_AFFECTED_RANGE.value
    fp1 = edge["fingerprint"]
    assert len(fp1) == 64

    # Second run (idempotent, identical results and fingerprint)
    resp2 = service.match_project_vulnerabilities(project_id)
    assert resp2.total_evaluated == 1
    assert resp2.affected_count == 1
    assert len(repo.affects_edges) == 1
    assert repo.affects_edges[("GHSA-test-01", "pv-lodash-4.17.20")]["fingerprint"] == fp1


def test_category_d_updating_result_after_advisory_changes() -> None:
    """When an advisory is updated (e.g. fixed version lowered to 4.17.20), re-evaluation clears AFFECTS."""
    repo = InMemoryVulnerabilityRepository()
    service = VersionMatchingService(repo=repo)
    project_id = "proj-124"

    # Initially affected: fixed: 4.17.21
    adv_v1 = [
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }
    ]
    repo.package_advisories[project_id] = [
        PackageAdvisoryPair(
            package_version_id="pv-lodash-4.17.20",
            package_name="lodash",
            package_version="4.17.20",
            ecosystem="npm",
            vulnerability_id="GHSA-test-02",
            affected_ranges=json.dumps(adv_v1),
            fixed_versions=["4.17.21"],
            summary="Test vuln",
            severity="HIGH",
        )
    ]
    service.match_project_vulnerabilities(project_id)
    assert ("GHSA-test-02", "pv-lodash-4.17.20") in repo.affects_edges

    # Advisory is corrected upstream: fixed is actually 4.17.20!
    adv_v2 = [
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.20"}]}],
        }
    ]
    repo.package_advisories[project_id] = [
        PackageAdvisoryPair(
            package_version_id="pv-lodash-4.17.20",
            package_name="lodash",
            package_version="4.17.20",
            ecosystem="npm",
            vulnerability_id="GHSA-test-02",
            affected_ranges=json.dumps(adv_v2),
            fixed_versions=["4.17.20"],
            summary="Test vuln",
            severity="HIGH",
        )
    ]
    resp2 = service.match_project_vulnerabilities(project_id)
    assert resp2.affected_count == 0
    assert resp2.not_affected_count == 1
    assert resp2.relationships_removed == 1
    # Confirmed not affected -> edge removed
    assert ("GHSA-test-02", "pv-lodash-4.17.20") not in repo.affects_edges


def test_category_d_multiple_advisories_for_one_package() -> None:
    """A package version can have multiple advisories evaluated independently."""
    repo = InMemoryVulnerabilityRepository()
    service = VersionMatchingService(repo=repo)
    project_id = "proj-125"

    repo.package_advisories[project_id] = [
        PackageAdvisoryPair(
            package_version_id="pv-pkg-1.0.0",
            package_name="multi-vuln-pkg",
            package_version="1.0.0",
            ecosystem="npm",
            vulnerability_id="ADV-1",
            affected_ranges=json.dumps([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]),
            fixed_versions=["2.0.0"],
            summary="Vuln 1",
            severity="CRITICAL",
        ),
        PackageAdvisoryPair(
            package_version_id="pv-pkg-1.0.0",
            package_name="multi-vuln-pkg",
            package_version="1.0.0",
            ecosystem="npm",
            vulnerability_id="ADV-2",
            affected_ranges=json.dumps([{"type": "SEMVER", "events": [{"introduced": "1.5.0"}, {"fixed": "2.0.0"}]}]),
            fixed_versions=["2.0.0"],
            summary="Vuln 2",
            severity="LOW",
        ),
    ]

    res = service.match_project_vulnerabilities(project_id)
    assert res.total_evaluated == 2
    assert res.affected_count == 1  # ADV-1 is affected (0..2.0.0)
    assert res.not_affected_count == 1  # ADV-2 is not affected (before introduced 1.5.0)
    assert ("ADV-1", "pv-pkg-1.0.0") in repo.affects_edges
    assert ("ADV-2", "pv-pkg-1.0.0") not in repo.affects_edges


def test_category_d_one_advisory_affecting_multiple_package_versions() -> None:
    """One advisory can match multiple package versions in the graph."""
    repo = InMemoryVulnerabilityRepository()
    service = VersionMatchingService(repo=repo)
    project_id = "proj-126"

    adv_json = json.dumps([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}])
    repo.package_advisories[project_id] = [
        PackageAdvisoryPair(
            package_version_id="pv-v1",
            package_name="shared-lib",
            package_version="1.0.0",
            ecosystem="npm",
            vulnerability_id="ADV-SHARED",
            affected_ranges=adv_json,
            fixed_versions=["2.0.0"],
            summary="Shared vuln",
            severity="HIGH",
        ),
        PackageAdvisoryPair(
            package_version_id="pv-v2",
            package_name="shared-lib",
            package_version="1.5.0",
            ecosystem="npm",
            vulnerability_id="ADV-SHARED",
            affected_ranges=adv_json,
            fixed_versions=["2.0.0"],
            summary="Shared vuln",
            severity="HIGH",
        ),
    ]

    res = service.match_project_vulnerabilities(project_id)
    assert res.affected_count == 2
    assert ("ADV-SHARED", "pv-v1") in repo.affects_edges
    assert ("ADV-SHARED", "pv-v2") in repo.affects_edges


def test_category_d_unsupported_ecosystem_returns_unknown() -> None:
    """Unsupported ecosystems return UNKNOWN and do not establish AFFECTS."""
    adv = AdvisoryData(
        id="OSV-TEST-018",
        affected=[
            OSVAffectedPackage(
                package_name="cargo-pkg",
                ecosystem="crates.io",
                ranges=[],
                versions=["1.0.0"],
            )
        ],
    )
    res = evaluate_version_against_advisory("cargo-pkg", "1.0.0", "crates.io", adv)
    assert res.status == MatchStatus.UNKNOWN
    assert res.reason_code == MatchReasonCode.UNSUPPORTED_ECOSYSTEM


# ==============================================================================
# Category E: Real Advisory Verification (npm & PyPI)
# ==============================================================================


def test_category_e_real_advisory_npm_lodash() -> None:
    """Verify real npm advisory GHSA-29mw-wpgm-hmr9 (lodash prototype pollution).
    
    Source: GitHub Security Advisory / OSV database
    Ecosystem: npm
    Introduced: 0
    Fixed: 4.17.21
    
    Expected Outcomes:
    - lodash@4.17.20 -> AFFECTED (falls within range < 4.17.21)
    - lodash@4.17.21 -> NOT_AFFECTED (at fixed version boundary 4.17.21)
    """
    lodash_advisory_data = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.17.21"},
                        ],
                    }
                ],
            }
        ],
    }
    adv = AdvisoryData.from_osv_dict(lodash_advisory_data)

    # 1. Evaluate affected version: 4.17.20
    res_affected = evaluate_version_against_advisory("lodash", "4.17.20", "npm", adv)
    assert res_affected.status == MatchStatus.AFFECTED
    assert res_affected.fixed_version == "4.17.21"
    assert res_affected.reason_code == MatchReasonCode.WITHIN_AFFECTED_RANGE
    assert "Version 4.17.20 is within affected range" in res_affected.reason

    # 2. Evaluate unaffected version: 4.17.21
    res_unaffected = evaluate_version_against_advisory("lodash", "4.17.21", "npm", adv)
    assert res_unaffected.status == MatchStatus.NOT_AFFECTED
    assert res_unaffected.fixed_version == "4.17.21"
    assert res_unaffected.reason_code == MatchReasonCode.AT_OR_ABOVE_FIXED_VERSION
    assert "Version 4.17.21 is at or above fixed version 4.17.21" in res_unaffected.reason


def test_category_e_real_advisory_pypi_requests() -> None:
    """Verify real PyPI advisory GHSA-652x-xj99-gmcc (requests session redirect auth leak).
    
    Source: GitHub Security Advisory / OSV database
    Ecosystem: PyPI
    Fixed: 2.3.0
    
    Expected Outcomes:
    - requests@2.2.1 -> AFFECTED (< 2.3.0)
    - requests@2.3.0 -> NOT_AFFECTED (at fixed version 2.3.0)
    """
    requests_advisory_data = {
        "id": "GHSA-652x-xj99-gmcc",
        "summary": "Session redirect auth leak in requests",
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.3.0"},
                        ],
                    }
                ],
            }
        ],
    }
    adv = AdvisoryData.from_osv_dict(requests_advisory_data)

    # 1. Evaluate affected version: 2.2.1
    res_aff = evaluate_version_against_advisory("requests", "2.2.1", "PyPI", adv)
    assert res_aff.status == MatchStatus.AFFECTED
    assert res_aff.fixed_version == "2.3.0"
    assert res_aff.reason_code == MatchReasonCode.WITHIN_AFFECTED_RANGE

    # 2. Evaluate unaffected version: 2.3.0
    res_unaff = evaluate_version_against_advisory("requests", "2.3.0", "PyPI", adv)
    assert res_unaff.status == MatchStatus.NOT_AFFECTED
    assert res_unaff.fixed_version == "2.3.0"
    assert res_unaff.reason_code == MatchReasonCode.AT_OR_ABOVE_FIXED_VERSION


# ==============================================================================
# Category F: API Route Integration Tests
# ==============================================================================

TEST_SECRET = "test_session_secret_that_is_at_least_32_chars_long!"


def auth_client(client: AsyncClient, mock_user_repo: InMemoryUserRepository) -> None:
    user = mock_user_repo.create_user(
        email="test_matching@vulnify.local",
        name="Matching Tester",
        password_hash="mock_hash",
        role="user",
    )
    token = create_session_jwt(
        user_id=user.id,
        email=user.email,
        role=user.role,
        secret=TEST_SECRET,
        ttl_minutes=480,
    )
    client.cookies.set(COOKIE_SESSION_NAME, token)


async def test_api_vulnerabilities_evaluate_endpoint(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
) -> None:
    """Test POST /api/vulnerabilities/evaluate endpoint."""
    auth_client(client, mock_user_repo)
    payload = {
        "package_name": "lodash",
        "package_version": "4.17.15",
        "ecosystem": "npm",
        "advisory": {
            "id": "GHSA-test-api",
            "summary": "Lodash vuln",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                        }
                    ],
                }
            ],
        },
    }
    resp = await client.post("/api/vulnerabilities/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "affected"
    assert data["fixed_version"] == "4.17.21"
    assert data["reason_code"] == "WITHIN_AFFECTED_RANGE"
    assert len(data["fingerprint"]) == 64


async def test_api_project_vulnerabilities_match_and_get(
    client: AsyncClient,
    mock_user_repo: InMemoryUserRepository,
    mock_project_repo: InMemoryProjectRepository,
) -> None:
    """Test POST /api/projects/{id}/vulnerabilities/match and GET /api/projects/{id}/vulnerabilities."""
    auth_client(client, mock_user_repo)
    project = mock_project_repo.create_project(
        name="Test Matching API Project",
        ecosystem="npm",
        description="API test project",
    )

    vuln_repo = InMemoryVulnerabilityRepository()
    adv_payload = [
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
            ],
        }
    ]
    vuln_repo.package_advisories[project.id] = [
        PackageAdvisoryPair(
            package_version_id="pv-lodash-1",
            package_name="lodash",
            package_version="4.17.20",
            ecosystem="npm",
            vulnerability_id="GHSA-test-match-api",
            affected_ranges=json.dumps(adv_payload),
            fixed_versions=["4.17.21"],
            summary="Lodash test vuln",
            severity="HIGH",
        )
    ]
    vuln_repo.vulnerabilities_data["GHSA-test-match-api"] = {
        "summary": "Lodash test vuln",
        "details": "Details here",
        "severity": "HIGH",
    }

    from vulnify.version_matching.service import get_version_matching_service
    client._transport.app.dependency_overrides[get_version_matching_service] = lambda: VersionMatchingService(repo=vuln_repo)

    # 1. Trigger matching
    match_resp = await client.post(f"/api/projects/{project.id}/vulnerabilities/match")
    assert match_resp.status_code == 200
    match_data = match_resp.json()
    assert match_data["total_evaluated"] == 1
    assert match_data["affected_count"] == 1
    assert match_data["relationships_persisted"] == 1
    assert len(match_data["results"]) == 1
    assert match_data["results"][0]["status"] == "affected"
    assert match_data["results"][0]["fixed_version"] == "4.17.21"

    # 2. Get findings
    findings_resp = await client.get(f"/api/projects/{project.id}/vulnerabilities")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) == 1
    assert findings[0]["id"] == "GHSA-test-match-api"
    assert findings[0]["package_name"] == "lodash"
    assert findings[0]["match_status"] == "affected"
    assert findings[0]["fixed_version"] == "4.17.21"


def test_falkor_vulnerability_repository_graph_persistence() -> None:
    """Live FalkorDB integration test verifying graph persistence, Cypher queries, and idempotency."""
    from vulnify.graph.client import get_graph_client
    from vulnify.graph.vulnerability_repository import FalkorVulnerabilityRepository

    try:
        client = get_graph_client()
        graph = client.get_graph()
        graph.query("RETURN 1")
    except Exception as exc:
        pytest.skip(f"FalkorDB is not reachable: {exc}")

    repo = FalkorVulnerabilityRepository(client=client)
    suffix = str(uuid.uuid4())[:8]
    pv_id = f"pv-test-{suffix}"
    vuln_id = f"GHSA-test-{suffix}"

    try:
        # Create test nodes
        graph.query("MERGE (pv:PackageVersion {id: $id, name: 'test-pkg', version: '1.0.0', ecosystem: 'npm'})", {"id": pv_id})
        graph.query("MERGE (v:Vulnerability {id: $id, summary: 'Test', details: '', severity: 'HIGH', aliases: [], published: '', modified: '', source_url: '', retrieved_at: 0})", {"id": vuln_id})

        match_res = VersionMatchResult(
            package_name="test-pkg",
            package_version="1.0.0",
            ecosystem="npm",
            advisory_id=vuln_id,
            status=MatchStatus.AFFECTED,
            reason_code=MatchReasonCode.WITHIN_AFFECTED_RANGE,
            reason="Version 1.0.0 is affected",
            matched_range="< 2.0.0",
            fixed_version="2.0.0",
            comparator="semver",
            evaluated_at=123456789,
            fingerprint="test-fingerprint-abc",
        )

        # 1. Persist affected match
        created, _ = repo.persist_match_results([(pv_id, match_res)], [])
        assert created == 1

        # Check edge properties in FalkorDB
        res = graph.query("MATCH (v:Vulnerability {id: $vid})-[r:AFFECTS]->(pv:PackageVersion {id: $pvid}) RETURN r.status, r.fixed_version, r.reason_code, r.fingerprint", {"vid": vuln_id, "pvid": pv_id})
        assert len(res.result_set) == 1
        assert res.result_set[0][0] == "affected"
        assert res.result_set[0][1] == "2.0.0"
        assert res.result_set[0][2] == "WITHIN_AFFECTED_RANGE"
        assert res.result_set[0][3] == "test-fingerprint-abc"

        # 2. Re-run matching (idempotent, no duplicate edges)
        repo.persist_match_results([(pv_id, match_res)], [])
        edge_count_res = graph.query("MATCH (v:Vulnerability {id: $vid})-[r:AFFECTS]->(pv:PackageVersion {id: $pvid}) RETURN count(r)", {"vid": vuln_id, "pvid": pv_id})
        assert edge_count_res.result_set[0][0] == 1

        # 3. Remove match when evaluated not affected
        repo.persist_match_results([], [(pv_id, match_res)])
        rem_res = graph.query("MATCH (v:Vulnerability {id: $vid})-[r:AFFECTS]->(pv:PackageVersion {id: $pvid}) RETURN count(r)", {"vid": vuln_id, "pvid": pv_id})
        assert rem_res.result_set[0][0] == 0
    finally:
        # Cleanup
        graph.query("MATCH (v:Vulnerability {id: $vid}) DETACH DELETE v", {"vid": vuln_id})
        graph.query("MATCH (pv:PackageVersion {id: $pvid}) DETACH DELETE pv", {"pvid": pv_id})


