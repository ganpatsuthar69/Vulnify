"""Deterministic scoring engine and priority ranking according to docs/scoring.md (US-301)."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


SCORING_VERSION = "v1.0.0"


class PriorityBand(str, Enum):
    HIGHEST = "Highest"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "unknown"


# Deterministic tie-breaker weights
PRIORITY_WEIGHTS: dict[str, int] = {
    PriorityBand.HIGHEST.value: 4,
    PriorityBand.HIGH.value: 3,
    PriorityBand.MEDIUM.value: 2,
    PriorityBand.LOW.value: 1,
    PriorityBand.UNKNOWN.value: 0,
}

SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MODERATE": 2,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

PATH_STATUS_WEIGHTS: dict[str, int] = {
    "path_found": 2,
    "unavailable": 1,
    "unknown": 1,
    "no_path_found": 0,
}


@dataclass(frozen=True)
class ScoringResult:
    """Deterministic result of evaluating a finding against the scoring policy."""

    priority: str
    reasons: list[str]
    reason_codes: list[str]
    scoring_version: str = SCORING_VERSION
    signals: dict[str, Any] = field(default_factory=dict)


def normalize_severity(severity: str | None) -> str:
    """Normalize severity classification string to standard uppercase token."""
    if not severity:
        return "UNKNOWN"
    s = str(severity).strip().upper()
    if s in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        return s
    return "UNKNOWN"


def normalize_path_status(path_status: str | None, path_depth: int | None = None) -> str:
    """Normalize path status, accounting for depth when provided."""
    if path_status is None:
        if path_depth is not None and path_depth >= 1:
            return "path_found"
        return "unavailable"

    ps = str(path_status).strip().lower()
    if ps == "path_found":
        return "path_found"
    if ps == "no_path_found":
        return "no_path_found"
    if ps in ("unavailable", "unknown"):
        return "unavailable"
    return "unavailable"


def score_finding(
    severity: str | None = None,
    match_status: str | None = "affected",
    path_status: str | None = "path_found",
    path_depth: int | None = None,
    fixed_version: str | None = None,
    triage_status: str | None = "open",
    is_known_exploited: bool | None = None,
    explicit_priority: str | None = None,
) -> ScoringResult:
    """Deterministically calculate finding priority band and transparent reasons.

    Rules conform strictly to docs/scoring.md (US-301).
    Missing signals are explicitly treated as 'unknown', never zero or absent risk.
    Identical inputs always produce identical outputs.
    """
    # 1. Normalize input signals
    norm_sev = normalize_severity(severity)
    norm_match = (match_status or "affected").strip().lower()
    norm_path = normalize_path_status(path_status, path_depth)
    norm_triage = (triage_status or "open").strip().lower()
    has_fix = bool(fixed_version and str(fixed_version).strip())
    clean_fix = str(fixed_version).strip() if has_fix else None

    # Track signals dictionary
    signals_dict: dict[str, Any] = {
        "severity": norm_sev if norm_sev != "UNKNOWN" else "unknown",
        "match_status": norm_match,
        "path_status": norm_path,
        "path_depth": path_depth,
        "fixed_version": clean_fix,
        "triage_status": norm_triage,
        "is_known_exploited": is_known_exploited,
    }

    reasons: list[str] = []
    reason_codes: list[str] = []

    # 2. Evaluate reason fragments
    # 2a. Severity reason
    if norm_sev == "CRITICAL":
        reasons.append("Advisory severity is Critical")
        reason_codes.append("SEVERITY_CRITICAL")
    elif norm_sev == "HIGH":
        reasons.append("Advisory severity is High")
        reason_codes.append("SEVERITY_HIGH")
    elif norm_sev in ("MODERATE", "MEDIUM"):
        reasons.append("Advisory severity is Moderate/Medium")
        reason_codes.append("SEVERITY_MEDIUM")
    elif norm_sev == "LOW":
        reasons.append("Advisory severity is Low")
        reason_codes.append("SEVERITY_LOW")
    else:
        reasons.append(
            "Advisory severity is unknown (missing upstream signal; treated with caution, not zero risk)"
        )
        reason_codes.append("SEVERITY_UNKNOWN")

    # 2b. Reachability reason
    if norm_path == "path_found":
        if path_depth == 1:
            reasons.append("Direct dependency reachable from service (path depth: 1 hop)")
            reason_codes.append("PATH_DIRECT_REACHABLE")
        elif path_depth is not None and path_depth > 1:
            reasons.append(f"Transitive dependency reachable from service (path depth: {path_depth} hops)")
            reason_codes.append("PATH_TRANSITIVE_REACHABLE")
        else:
            reasons.append("Dependency path confirmed reachable from service")
            reason_codes.append("PATH_CONFIRMED_REACHABLE")
    elif norm_path == "no_path_found":
        reasons.append(
            "No service dependency path found within analyzed traversal bounds (does not guarantee absence of risk)"
        )
        reason_codes.append("PATH_NOT_FOUND")
    else:
        reasons.append(
            "Dependency path reachability unknown (service topology traversal pending or unavailable; not assumed safe)"
        )
        reason_codes.append("PATH_UNKNOWN")

    # 2c. Remediation / Fixed version reason
    if has_fix and clean_fix:
        reasons.append(f"Actionable remediation target available (fixed in >= {clean_fix})")
        reason_codes.append("FIX_VERSION_AVAILABLE")
    else:
        reasons.append("Remediation target unknown (no published fixed version in upstream advisory)")
        reason_codes.append("FIX_VERSION_UNKNOWN")

    # 2d. Triage or review reason
    if norm_triage in ("fixed", "not_affected"):
        reasons.append(f"Finding resolved or dismissed via triage status '{norm_triage}'")
        reason_codes.append("TRIAGE_STATUS_RESOLVED")
    elif norm_triage == "under_investigation":
        reasons.append("Finding currently under active security investigation")
        reason_codes.append("TRIAGE_UNDER_INVESTIGATION")

    # 2e. Version match reason
    if norm_match == "not_affected":
        reasons.append("Version evaluation confirmed package is not affected by advisory constraints")
        reason_codes.append("MATCH_STATUS_NOT_AFFECTED")

    # 2f. Known exploitation threat reason
    if is_known_exploited is True:
        reasons.append("Known active exploitation reported in public threat intelligence")
        reason_codes.append("KNOWN_EXPLOITED_ACTIVE")

    # 3. Priority band determination
    # Check if explicit override is present (e.g. from human triage override or test fixture)
    if explicit_priority and explicit_priority.strip():
        ep = explicit_priority.strip()
        # Canonicalize case if matching known bands
        canonical = next(
            (b.value for b in PriorityBand if b.value.lower() == ep.lower()),
            ep,
        )
        return ScoringResult(
            priority=canonical,
            reasons=reasons,
            reason_codes=reason_codes,
            scoring_version=SCORING_VERSION,
            signals=signals_dict,
        )

    # Rule 1: Triage resolution or confirmed not affected -> Low
    if norm_triage in ("fixed", "not_affected") or norm_match == "not_affected":
        priority = PriorityBand.LOW.value

    # Rule 2: Active known-exploitation signal (US-302 forward-compatibility)
    elif is_known_exploited is True:
        if norm_path == "path_found" or norm_sev == "CRITICAL":
            priority = PriorityBand.HIGHEST.value
        else:
            priority = PriorityBand.HIGH.value

    # Rule 3: Confirmed affected package version
    elif norm_match == "affected":
        if norm_path == "path_found":
            if norm_sev == "CRITICAL":
                priority = PriorityBand.HIGHEST.value
            elif norm_sev == "HIGH":
                priority = PriorityBand.HIGH.value
            elif norm_sev in ("MODERATE", "MEDIUM", "LOW"):
                priority = PriorityBand.MEDIUM.value
            else:  # UNKNOWN severity with confirmed path -> cautious Medium
                priority = PriorityBand.MEDIUM.value
        elif norm_path == "no_path_found":
            if norm_sev == "LOW":
                priority = PriorityBand.LOW.value
            elif norm_sev in ("CRITICAL", "HIGH"):
                # Unconfirmed exposure, but advisory is Critical/High -> Medium with disclaimer
                priority = PriorityBand.MEDIUM.value
            elif norm_sev in ("MODERATE", "MEDIUM"):
                priority = PriorityBand.MEDIUM.value
            else:  # UNKNOWN severity + no path -> Medium (missing severity is unknown risk, not zero risk)
                priority = PriorityBand.MEDIUM.value
        else:
            # path is unavailable / unknown -> conservative Medium
            priority = PriorityBand.MEDIUM.value

    # Rule 4: Match status is unknown
    else:
        if norm_sev in ("CRITICAL", "HIGH"):
            priority = PriorityBand.MEDIUM.value
        else:
            priority = PriorityBand.LOW.value

    return ScoringResult(
        priority=priority,
        reasons=reasons,
        reason_codes=reason_codes,
        scoring_version=SCORING_VERSION,
        signals=signals_dict,
    )


def finding_sort_key(finding: dict[str, Any] | Any) -> tuple:
    """Return a deterministic sort key tuple for ordering findings.

    Sequential tie-breaker order (docs/scoring.md section 4):
    1. Priority Band Weight (Highest: 4, High: 3, Medium: 2, Low: 1, unknown: 0) DESC
    2. Advisory Severity Rank (CRITICAL: 4, HIGH: 3, MODERATE/MEDIUM: 2, LOW: 1, UNKNOWN: 0) DESC
    3. Path Presence (path_found: 2, unavailable: 1, no_path_found: 0) DESC
    4. Path Depth (1 direct < 2 transitive < null depth 999) ASC
    5. Actionable Remediation (has fixed version > no fix) DESC
    6. Alphanumeric tie-breaker: advisory_id ASC, package_name ASC, service_name ASC, id ASC
    """
    get = (
        (lambda k, default=None: getattr(finding, k, default))
        if hasattr(finding, "__dict__") and not isinstance(finding, dict)
        else (lambda k, default=None: finding.get(k, default))  # type: ignore[union-attr]
    )

    p_raw = str(get("priority", "unknown")).strip()
    p_canonical = next(
        (b.value for b in PriorityBand if b.value.lower() == p_raw.lower()),
        p_raw,
    )
    p_weight = PRIORITY_WEIGHTS.get(p_canonical, 0)

    sev_raw = normalize_severity(get("severity"))
    s_weight = SEVERITY_WEIGHTS.get(sev_raw, 0)

    path_raw = normalize_path_status(get("path_status"), get("path_depth"))
    path_weight = PATH_STATUS_WEIGHTS.get(path_raw, 0)

    depth = get("path_depth")
    depth_val = depth if (isinstance(depth, int) and depth > 0) else 999

    has_fix = 1 if bool(get("fixed_version")) else 0

    adv_id = str(get("advisory_id", "")).lower()
    pkg_name = str(get("package_name", "")).lower()
    svc_name = str(get("service_name", "")).lower()
    fid = str(get("id", "")).lower()

    return (
        -p_weight,     # 1. Band weight desc
        -s_weight,     # 2. Severity rank desc
        -path_weight,  # 3. Path presence desc
        depth_val,     # 4. Path depth asc
        -has_fix,      # 5. Has fix desc
        adv_id,        # 6a. Advisory ID asc
        pkg_name,      # 6b. Package name asc
        svc_name,      # 6c. Service name asc
        fid,           # 6d. Finding ID asc
    )
