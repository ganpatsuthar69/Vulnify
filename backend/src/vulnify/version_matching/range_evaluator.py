"""Evaluator interpreting OSV affected ranges against package versions using ecosystem comparators."""

from datetime import datetime, timezone
import re
import time
from vulnify.version_matching.comparators.base import (
    BaseVersionComparator,
    InvalidVersionError,
    UnsupportedEcosystemError,
)
from vulnify.version_matching.comparators.registry import (
    get_comparator,
    get_range_comparator,
)
from vulnify.version_matching.models import (
    AdvisoryData,
    MatchReasonCode,
    MatchStatus,
    OSVAffectedPackage,
    OSVRange,
    VersionMatchResult,
)


def _name_key(name: str, ecosystem: str) -> str:
    """Compare key for a package name; PEP 503 makes '-', '_' and '.' equivalent for PyPI."""
    normalized = name.strip().lower()
    if ecosystem.strip().lower() in ("pypi", "python"):
        return re.sub(r"[-_.]+", "-", normalized)
    return normalized


def evaluate_version_against_advisory(
    package_name: str,
    package_version: str,
    ecosystem: str,
    advisory: AdvisoryData,
) -> VersionMatchResult:
    """Evaluate whether an installed package version is affected by an OSV advisory.
    
    Adheres strictly to ecosystem semantics and the OSV schema specification:
    - Explicit affected version lists
    - SEMVER and ECOSYSTEM ranges
    - introduced, fixed, last_affected, and limit event boundaries
    """
    now = int(datetime.now(timezone.utc).timestamp())

    # 1. Validate package metadata
    if not package_name or not package_name.strip() or not package_version or not package_version.strip() or not ecosystem or not ecosystem.strip():
        res = VersionMatchResult(
            package_name=package_name or "",
            package_version=package_version or "",
            ecosystem=ecosystem or "",
            advisory_id=advisory.id,
            status=MatchStatus.UNKNOWN,
            reason_code=MatchReasonCode.MISSING_PACKAGE_METADATA,
            reason="Package name, version, or ecosystem metadata is missing.",
            evaluated_at=now,
        )
        return res.with_fingerprint()

    clean_pkg_name = package_name.strip()
    clean_version = package_version.strip()
    clean_ecosystem = ecosystem.strip()

    # 2. Retrieve ecosystem comparator
    try:
        comparator = get_comparator(clean_ecosystem)
    except UnsupportedEcosystemError as exc:
        res = VersionMatchResult(
            package_name=clean_pkg_name,
            package_version=clean_version,
            ecosystem=clean_ecosystem,
            advisory_id=advisory.id,
            status=MatchStatus.UNKNOWN,
            reason_code=MatchReasonCode.UNSUPPORTED_ECOSYSTEM,
            reason=str(exc),
            evaluated_at=now,
        )
        return res.with_fingerprint()

    # 3. Validate installed version string against ecosystem grammar
    try:
        comparator.parse(clean_version)
    except InvalidVersionError as exc:
        res = VersionMatchResult(
            package_name=clean_pkg_name,
            package_version=clean_version,
            ecosystem=clean_ecosystem,
            advisory_id=advisory.id,
            status=MatchStatus.UNKNOWN,
            reason_code=MatchReasonCode.INVALID_VERSION,
            reason=f"Installed version '{clean_version}' is invalid under {clean_ecosystem} rules: {exc}",
            comparator=comparator.name,
            evaluated_at=now,
        )
        return res.with_fingerprint()

    # 4. Locate relevant affected package entries in the advisory
    package_key = _name_key(clean_pkg_name, clean_ecosystem)
    matching_affected: list[OSVAffectedPackage] = [
        aff for aff in advisory.affected
        if _name_key(aff.package_name, clean_ecosystem) == package_key
        and aff.ecosystem.strip().lower() == clean_ecosystem.lower()
    ]

    if not matching_affected:
        res = VersionMatchResult(
            package_name=clean_pkg_name,
            package_version=clean_version,
            ecosystem=clean_ecosystem,
            advisory_id=advisory.id,
            status=MatchStatus.NOT_AFFECTED,
            reason_code=MatchReasonCode.OUTSIDE_AFFECTED_RANGES,
            reason=f"Advisory {advisory.id} does not target package '{clean_pkg_name}' in ecosystem '{clean_ecosystem}'.",
            comparator=comparator.name,
            evaluated_at=now,
        )
        return res.with_fingerprint()

    had_malformed_range = False
    malformed_range_reason = ""
    had_unsupported_range_type = False
    known_fixed_versions: list[str] = []
    known_introduced_versions: list[str] = []

    # 5. Evaluate matching affected package entries
    for aff in matching_affected:
        # 5a. Check explicit versions list
        for explicit_v in aff.versions:
            if not explicit_v or not explicit_v.strip():
                continue
            clean_exp_v = explicit_v.strip()
            try:
                if comparator.compare(clean_version, clean_exp_v) == 0:
                    return VersionMatchResult(
                        package_name=clean_pkg_name,
                        package_version=clean_version,
                        ecosystem=clean_ecosystem,
                        advisory_id=advisory.id,
                        status=MatchStatus.AFFECTED,
                        reason_code=MatchReasonCode.EXPLICIT_VERSION_MATCH,
                        reason=f"Version {clean_version} matches explicit affected version {clean_exp_v} in advisory {advisory.id}.",
                        matched_range=f"={clean_exp_v}",
                        comparator=comparator.name,
                        evaluated_at=now,
                    ).with_fingerprint()
            except InvalidVersionError:
                # If one version in explicit list cannot be parsed, ignore it and continue
                continue

        # 5b. Check affected ranges
        for r_idx, range_obj in enumerate(aff.ranges):
            rtype = range_obj.type.strip().upper() if range_obj.type else ""

            if rtype == "GIT":
                had_unsupported_range_type = True
                continue

            try:
                range_comp = get_range_comparator(range_obj.type, clean_ecosystem)
            except (ValueError, UnsupportedEcosystemError):
                had_unsupported_range_type = True
                continue

            # Process events list into spans:
            # Each span starts with an 'introduced' event and ends with 'fixed', 'last_affected', 'limit', or is open-ended.
            events = range_obj.events
            if not events:
                had_malformed_range = True
                malformed_range_reason = f"Range {r_idx} in advisory {advisory.id} contains no events."
                continue

            # Break events into ordered spans
            spans: list[dict[str, str | None]] = []
            current_span: dict[str, str | None] = {"introduced": None, "fixed": None, "last_affected": None, "limit": None}
            has_introduced = False

            for ev in events:
                if ev.introduced is not None:
                    if has_introduced:
                        # Previous span had no explicit end event -> open-ended span
                        spans.append(current_span)
                        current_span = {"introduced": None, "fixed": None, "last_affected": None, "limit": None}
                    current_span["introduced"] = ev.introduced.strip()
                    has_introduced = True
                elif ev.fixed is not None:
                    current_span["fixed"] = ev.fixed.strip()
                    spans.append(current_span)
                    current_span = {"introduced": None, "fixed": None, "last_affected": None, "limit": None}
                    has_introduced = False
                elif ev.last_affected is not None:
                    current_span["last_affected"] = ev.last_affected.strip()
                    spans.append(current_span)
                    current_span = {"introduced": None, "fixed": None, "last_affected": None, "limit": None}
                    has_introduced = False
                elif ev.limit is not None:
                    current_span["limit"] = ev.limit.strip()
                    spans.append(current_span)
                    current_span = {"introduced": None, "fixed": None, "last_affected": None, "limit": None}
                    has_introduced = False

            if has_introduced:
                # Open-ended final span
                spans.append(current_span)

            # Evaluate installed version against each span
            for span in spans:
                intro = span["introduced"]
                fixed = span["fixed"]
                last_aff = span["last_affected"]
                limit = span["limit"]

                if intro:
                    known_introduced_versions.append(intro)
                if fixed:
                    known_fixed_versions.append(fixed)

                # 1. Lower bound check
                lower_satisfied = False
                if intro is None or intro == "0":
                    lower_satisfied = True
                else:
                    try:
                        lower_satisfied = (range_comp.compare(clean_version, intro) >= 0)
                    except InvalidVersionError as exc:
                        had_malformed_range = True
                        malformed_range_reason = f"Invalid introduced version '{intro}': {exc}"
                        continue

                # 2. Upper bound check
                upper_satisfied = True
                if fixed is not None:
                    try:
                        upper_satisfied = (range_comp.compare(clean_version, fixed) < 0)
                    except InvalidVersionError as exc:
                        had_malformed_range = True
                        malformed_range_reason = f"Invalid fixed version '{fixed}': {exc}"
                        continue
                elif last_aff is not None:
                    try:
                        upper_satisfied = (range_comp.compare(clean_version, last_aff) <= 0)
                    except InvalidVersionError as exc:
                        had_malformed_range = True
                        malformed_range_reason = f"Invalid last_affected version '{last_aff}': {exc}"
                        continue
                elif limit is not None:
                    try:
                        upper_satisfied = (range_comp.compare(clean_version, limit) < 0)
                    except InvalidVersionError as exc:
                        had_malformed_range = True
                        malformed_range_reason = f"Invalid limit version '{limit}': {exc}"
                        continue

                # Both bounds satisfied -> Version is AFFECTED
                if lower_satisfied and upper_satisfied:
                    # Construct clean range label
                    if fixed:
                        if intro and intro != "0":
                            range_label = f">= {intro}, < {fixed}"
                        else:
                            range_label = f"< {fixed}"
                    elif last_aff:
                        if intro and intro != "0":
                            range_label = f">= {intro}, <= {last_aff}"
                        else:
                            range_label = f"<= {last_aff}"
                    elif limit:
                        if intro and intro != "0":
                            range_label = f">= {intro}, < limit {limit}"
                        else:
                            range_label = f"< limit {limit}"
                    else:
                        if intro and intro != "0":
                            range_label = f">= {intro}"
                        else:
                            range_label = "all versions"

                    return VersionMatchResult(
                        package_name=clean_pkg_name,
                        package_version=clean_version,
                        ecosystem=clean_ecosystem,
                        advisory_id=advisory.id,
                        status=MatchStatus.AFFECTED,
                        reason_code=MatchReasonCode.WITHIN_AFFECTED_RANGE,
                        reason=f"Version {clean_version} is within affected range ({range_label}) for advisory {advisory.id}.",
                        matched_range=range_label,
                        fixed_version=fixed,
                        comparator=range_comp.name,
                        evaluated_at=now,
                    ).with_fingerprint()

    # 6. If no affected match, determine the safe reason or unknown state
    if had_malformed_range:
        return VersionMatchResult(
            package_name=clean_pkg_name,
            package_version=clean_version,
            ecosystem=clean_ecosystem,
            advisory_id=advisory.id,
            status=MatchStatus.UNKNOWN,
            reason_code=MatchReasonCode.MALFORMED_RANGE,
            reason=f"Unable to reliably determine match: {malformed_range_reason}",
            comparator=comparator.name,
            evaluated_at=now,
        ).with_fingerprint()

    if had_unsupported_range_type and not known_fixed_versions and not known_introduced_versions:
        return VersionMatchResult(
            package_name=clean_pkg_name,
            package_version=clean_version,
            ecosystem=clean_ecosystem,
            advisory_id=advisory.id,
            status=MatchStatus.UNKNOWN,
            reason_code=MatchReasonCode.UNSUPPORTED_RANGE_TYPE,
            reason=f"Advisory {advisory.id} contains unsupported range types (e.g. GIT commit ranges).",
            comparator=comparator.name,
            evaluated_at=now,
        ).with_fingerprint()

    # 7. Check if safely at or above a known fixed boundary
    if known_fixed_versions:
        # Check against the highest or closest fixed version
        closest_fixed = None
        for fv in known_fixed_versions:
            try:
                if comparator.compare(clean_version, fv) >= 0:
                    closest_fixed = fv
                    break
            except InvalidVersionError:
                continue

        if closest_fixed:
            return VersionMatchResult(
                package_name=clean_pkg_name,
                package_version=clean_version,
                ecosystem=clean_ecosystem,
                advisory_id=advisory.id,
                status=MatchStatus.NOT_AFFECTED,
                reason_code=MatchReasonCode.AT_OR_ABOVE_FIXED_VERSION,
                reason=f"Version {clean_version} is at or above fixed version {closest_fixed} for advisory {advisory.id}.",
                fixed_version=closest_fixed,
                comparator=comparator.name,
                evaluated_at=now,
            ).with_fingerprint()

    # 8. Check if strictly before introduced version
    if known_introduced_versions:
        is_strictly_before_all = True
        earliest_intro = known_introduced_versions[0]
        for iv in known_introduced_versions:
            if iv == "0":
                is_strictly_before_all = False
                break
            try:
                if comparator.compare(clean_version, iv) >= 0:
                    is_strictly_before_all = False
                    break
            except InvalidVersionError:
                continue

        if is_strictly_before_all and earliest_intro != "0":
            return VersionMatchResult(
                package_name=clean_pkg_name,
                package_version=clean_version,
                ecosystem=clean_ecosystem,
                advisory_id=advisory.id,
                status=MatchStatus.NOT_AFFECTED,
                reason_code=MatchReasonCode.BEFORE_INTRODUCED_VERSION,
                reason=f"Version {clean_version} is before introduced version {earliest_intro} for advisory {advisory.id}.",
                comparator=comparator.name,
                evaluated_at=now,
            ).with_fingerprint()

    # 9. Outside all defined ranges
    return VersionMatchResult(
        package_name=clean_pkg_name,
        package_version=clean_version,
        ecosystem=clean_ecosystem,
        advisory_id=advisory.id,
        status=MatchStatus.NOT_AFFECTED,
        reason_code=MatchReasonCode.OUTSIDE_AFFECTED_RANGES,
        reason=f"Version {clean_version} falls outside all affected ranges for advisory {advisory.id}.",
        comparator=comparator.name,
        evaluated_at=now,
    ).with_fingerprint()
