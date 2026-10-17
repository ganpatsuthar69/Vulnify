"""Typed data models and enumeration types for ecosystem-aware version matching."""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any


class MatchStatus(str, Enum):
    """Evaluation status for version matching against an advisory."""
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


class MatchReasonCode(str, Enum):
    """Machine-readable reason code explaining the matching decision."""
    WITHIN_AFFECTED_RANGE = "WITHIN_AFFECTED_RANGE"
    EXPLICIT_VERSION_MATCH = "EXPLICIT_VERSION_MATCH"
    AT_OR_ABOVE_FIXED_VERSION = "AT_OR_ABOVE_FIXED_VERSION"
    BEFORE_INTRODUCED_VERSION = "BEFORE_INTRODUCED_VERSION"
    OUTSIDE_AFFECTED_RANGES = "OUTSIDE_AFFECTED_RANGES"
    MISSING_PACKAGE_METADATA = "MISSING_PACKAGE_METADATA"
    INVALID_VERSION = "INVALID_VERSION"
    MALFORMED_RANGE = "MALFORMED_RANGE"
    UNSUPPORTED_RANGE_TYPE = "UNSUPPORTED_RANGE_TYPE"
    UNSUPPORTED_ECOSYSTEM = "UNSUPPORTED_ECOSYSTEM"


@dataclass(frozen=True)
class OSVRangeEvent:
    """A single event boundary in an OSV range specification."""
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None


@dataclass(frozen=True)
class OSVRange:
    """An affected range container with range type (SEMVER, ECOSYSTEM, GIT) and ordered events."""
    type: str
    events: list[OSVRangeEvent] = field(default_factory=list)


@dataclass(frozen=True)
class OSVAffectedPackage:
    """An affected package definition in an OSV record."""
    package_name: str
    ecosystem: str
    ranges: list[OSVRange] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)


@dataclass
class AdvisoryData:
    """Normalized advisory representation extracted from OSV JSON."""
    id: str
    summary: str | None = None
    details: str | None = None
    severity: str | None = None
    affected: list[OSVAffectedPackage] = field(default_factory=list)
    source_url: str | None = None
    retrieved_at: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_osv_dict(cls, data: dict[str, Any]) -> "AdvisoryData":
        """Construct AdvisoryData from a raw OSV dictionary."""
        vuln_id = str(data.get("id") or "").strip()
        summary = str(data.get("summary") or "").strip() or None
        details = str(data.get("details") or "").strip() or None
        severity = None
        db_spec = data.get("database_specific")
        if isinstance(db_spec, dict) and db_spec.get("severity"):
            severity = str(db_spec.get("severity")).strip().upper()

        affected_list: list[OSVAffectedPackage] = []
        raw_affected = data.get("affected") or []
        if isinstance(raw_affected, list):
            for aff in raw_affected:
                if not isinstance(aff, dict):
                    continue
                pkg = aff.get("package") or {}
                pkg_name = str(pkg.get("name") or "").strip()
                ecosystem = str(pkg.get("ecosystem") or "").strip()
                versions = [str(v).strip() for v in aff.get("versions") or [] if str(v).strip()]
                ranges: list[OSVRange] = []
                for r in aff.get("ranges") or []:
                    if not isinstance(r, dict):
                        continue
                    rtype = str(r.get("type") or "").strip()
                    events: list[OSVRangeEvent] = []
                    for ev in r.get("events") or []:
                        if not isinstance(ev, dict):
                            continue
                        events.append(
                            OSVRangeEvent(
                                introduced=str(ev["introduced"]).strip() if "introduced" in ev else None,
                                fixed=str(ev["fixed"]).strip() if "fixed" in ev else None,
                                last_affected=str(ev["last_affected"]).strip() if "last_affected" in ev else None,
                                limit=str(ev["limit"]).strip() if "limit" in ev else None,
                            )
                        )
                    ranges.append(OSVRange(type=rtype, events=events))
                affected_list.append(
                    OSVAffectedPackage(
                        package_name=pkg_name,
                        ecosystem=ecosystem,
                        ranges=ranges,
                        versions=versions,
                    )
                )

        return cls(
            id=vuln_id,
            summary=summary,
            details=details,
            severity=severity,
            affected=affected_list,
            raw=data,
        )

    @classmethod
    def from_stored(
        cls,
        vuln_id: str,
        affected_ranges_raw: str | list[Any],
        summary: str | None = None,
        details: str | None = None,
        severity: str | None = None,
        fallback_pkg_name: str = "",
        fallback_ecosystem: str = "",
    ) -> "AdvisoryData":
        """Construct AdvisoryData from stored FalkorDB records or serialized JSON."""
        if isinstance(affected_ranges_raw, str):
            try:
                items = json.loads(affected_ranges_raw)
            except Exception:
                items = []
        elif isinstance(affected_ranges_raw, list):
            items = affected_ranges_raw
        else:
            items = []

        affected_list: list[OSVAffectedPackage] = []
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                if "package" in item:
                    pkg = item.get("package") or {}
                    p_name = str(pkg.get("name") or fallback_pkg_name).strip()
                    p_eco = str(pkg.get("ecosystem") or fallback_ecosystem).strip()
                    versions = [str(v).strip() for v in item.get("versions") or [] if str(v).strip()]
                    ranges: list[OSVRange] = []
                    for r in item.get("ranges") or []:
                        if not isinstance(r, dict):
                            continue
                        rtype = str(r.get("type") or "").strip()
                        events: list[OSVRangeEvent] = []
                        for ev in r.get("events") or []:
                            if not isinstance(ev, dict):
                                continue
                            events.append(
                                OSVRangeEvent(
                                    introduced=str(ev["introduced"]).strip() if "introduced" in ev else None,
                                    fixed=str(ev["fixed"]).strip() if "fixed" in ev else None,
                                    last_affected=str(ev["last_affected"]).strip() if "last_affected" in ev else None,
                                    limit=str(ev["limit"]).strip() if "limit" in ev else None,
                                )
                            )
                        ranges.append(OSVRange(type=rtype, events=events))
                    affected_list.append(
                        OSVAffectedPackage(
                            package_name=p_name,
                            ecosystem=p_eco,
                            ranges=ranges,
                            versions=versions,
                        )
                    )
                elif "type" in item:
                    rtype = str(item.get("type") or "").strip()
                    events = []
                    for ev in item.get("events") or []:
                        if not isinstance(ev, dict):
                            continue
                        events.append(
                            OSVRangeEvent(
                                introduced=str(ev["introduced"]).strip() if "introduced" in ev else None,
                                fixed=str(ev["fixed"]).strip() if "fixed" in ev else None,
                                last_affected=str(ev["last_affected"]).strip() if "last_affected" in ev else None,
                                limit=str(ev["limit"]).strip() if "limit" in ev else None,
                            )
                        )
                    if not affected_list:
                        affected_list.append(
                            OSVAffectedPackage(
                                package_name=fallback_pkg_name,
                                ecosystem=fallback_ecosystem,
                                ranges=[],
                                versions=[],
                            )
                        )
                    affected_list[0].ranges.append(OSVRange(type=rtype, events=events))

        return cls(
            id=vuln_id,
            summary=summary,
            details=details,
            severity=severity,
            affected=affected_list,
        )


@dataclass(frozen=True)
class VersionMatchResult:
    """The result of evaluating an installed package version against an advisory."""
    package_name: str
    package_version: str
    ecosystem: str
    advisory_id: str
    status: MatchStatus
    reason_code: MatchReasonCode
    reason: str
    matched_range: str | None = None
    fixed_version: str | None = None
    comparator: str = "unknown"
    evaluated_at: int = 0
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        """Derive a deterministic digest over the inputs determining this match decision."""
        data = f"{self.package_name}:{self.package_version}:{self.ecosystem}:{self.advisory_id}:{self.status.value}:{self.matched_range}:{self.fixed_version}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def with_fingerprint(self) -> "VersionMatchResult":
        """Return a copy of this result with its deterministic fingerprint computed."""
        return VersionMatchResult(
            **{**self.__dict__, "fingerprint": self.compute_fingerprint()}
        )
