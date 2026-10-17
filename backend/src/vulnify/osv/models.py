"""Data models for OSV API request, response, and normalized advisory structures."""

from dataclasses import dataclass, field
import json
from typing import Any


@dataclass(frozen=True)
class OsvPackage:
    name: str
    ecosystem: str


@dataclass(frozen=True)
class OsvQuery:
    package: OsvPackage
    version: str

    @property
    def cache_key(self) -> str:
        return f"{self.package.ecosystem.strip().lower()}:{self.package.name.strip().lower()}:{self.version.strip()}"

    def to_api_payload(self) -> dict[str, Any]:
        return {
            "package": {
                "name": self.package.name.strip(),
                "ecosystem": self.package.ecosystem.strip(),
            },
            "version": self.version.strip(),
        }


from vulnify.models import VulnerabilityRecord

# Backward compatibility alias
OsvVulnerability = VulnerabilityRecord


def parse_osv_vulnerability(data: dict[str, Any], retrieved_at: int) -> OsvVulnerability:
    """Parse a raw OSV vulnerability payload into a normalized, safe OsvVulnerability model."""
    vuln_id = str(data.get("id") or "").strip()
    summary = str(data.get("summary") or "").strip()
    details = str(data.get("details") or "").strip()

    # Extract aliases (e.g. CVE-..., GHSA-...)
    raw_aliases = data.get("aliases") or []
    aliases: list[str] = [str(a).strip() for a in raw_aliases if str(a).strip()]

    # Extract severity classification and CVSS score
    severity = "UNKNOWN"
    cvss: str | None = None

    # Check database_specific for severity (e.g. GitHub Advisory severity)
    db_spec = data.get("database_specific")
    if isinstance(db_spec, dict) and db_spec.get("severity"):
        severity = str(db_spec.get("severity")).strip().upper()

    # Check severity array for CVSS scores
    raw_severities = data.get("severity") or []
    if isinstance(raw_severities, list):
        for sev in raw_severities:
            if isinstance(sev, dict):
                score = sev.get("score")
                if score and not cvss:
                    cvss = str(score).strip()
                sev_type = str(sev.get("type", "")).upper()
                if "CVSS" in sev_type and severity == "UNKNOWN":
                    # Derive qualitative rating if not already set from database_specific
                    severity = "MODERATE"

    # Extract affected ranges, packages, and fixed versions
    affected_packages_list: list[dict[str, Any]] = []
    fixed_versions_set: set[str] = set()

    raw_affected = data.get("affected") or []
    if isinstance(raw_affected, list):
        for aff in raw_affected:
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package") or {}
            ranges = aff.get("ranges") or []
            versions = aff.get("versions") or []
            clean_ranges = []
            if isinstance(ranges, list):
                for r in ranges:
                    if isinstance(r, dict):
                        clean_ranges.append(r)
                        events = r.get("events") or []
                        if isinstance(events, list):
                            for ev in events:
                                if isinstance(ev, dict) and "fixed" in ev:
                                    fix = str(ev["fixed"]).strip()
                                    if fix:
                                        fixed_versions_set.add(fix)
            affected_packages_list.append({
                "package": {
                    "name": str(pkg.get("name") or "").strip(),
                    "ecosystem": str(pkg.get("ecosystem") or "").strip(),
                },
                "ranges": clean_ranges,
                "versions": [str(v).strip() for v in versions if str(v).strip()] if isinstance(versions, list) else [],
            })

    # Extract references
    references_list: list[str] = []
    raw_refs = data.get("references") or []
    if isinstance(raw_refs, list):
        for ref in raw_refs:
            if isinstance(ref, dict) and ref.get("url"):
                url = str(ref["url"]).strip()
                if url:
                    references_list.append(url)

    # Source URL: use first advisory/web reference if available, or official OSV permalink
    source_url = f"https://osv.dev/vulnerability/{vuln_id}"
    for ref_url in references_list:
        if "advisories" in ref_url or "github.com" in ref_url or "nvd.nist.gov" in ref_url:
            source_url = ref_url
            break

    published = str(data["published"]).strip() if data.get("published") else None
    modified = str(data["modified"]).strip() if data.get("modified") else None

    return OsvVulnerability(
        id=vuln_id,
        summary=summary or f"Vulnerability {vuln_id}",
        details=details,
        severity=severity,
        cvss=cvss,
        aliases=aliases,
        affected_ranges=json.dumps(affected_packages_list),
        fixed_versions=sorted(fixed_versions_set),
        references=references_list[:20],  # cap to top 20 references
        source_url=source_url,
        published=published,
        modified=modified,
        retrieved_at=retrieved_at,
        source="OSV",
    )
