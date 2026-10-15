"""Severity from an OSV record: distro rating first (it knows the distro build), CVSS as fallback."""

import re
from dataclasses import dataclass

from cvss import CVSS3, CVSS4

LEVELS = ["low", "medium", "high", "critical"]  # "unknown" sits outside the ladder

_VENDOR_MAP = {
    "negligible": "low", "unimportant": "low", "low": "low",
    "medium": "medium", "moderate": "medium",
    "high": "high", "important": "high",
    "critical": "critical",
}


@dataclass
class Severity:
    level: str               # low|medium|high|critical|unknown
    cvss: float | None
    vendor: str | None       # raw distro rating, e.g. "Important", "medium", "unimportant"
    attack_vector: str = ""  # N(etwork) / A(djacent) / L(ocal) / P(hysical) from the CVSS vector

    @property
    def rank(self) -> int:
        return LEVELS.index(self.level) + 1 if self.level in LEVELS else 0

    def label(self) -> str:
        parts = [self.level.upper()]
        if self.cvss is not None:
            parts.append(f"CVSS {self.cvss:.1f}")
        if self.attack_vector:
            parts.append(f"AV:{self.attack_vector}")
        if self.vendor:
            parts.append(f"distro: {self.vendor}")
        return " · ".join(parts)


def _cvss_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _cvss_score(entry: dict) -> float | None:
    vec = entry.get("score", "")
    try:
        if vec.startswith("CVSS:4"):
            return float(CVSS4(vec).base_score)
        if vec.startswith("CVSS:3"):
            return float(CVSS3(vec).scores()[0])
    except Exception:
        return None
    return None


def severity_of(vuln: dict, affected: dict | None) -> Severity:
    scores = [s for s in (_cvss_score(e) for e in vuln.get("severity", [])) if s is not None]
    cvss = max(scores) if scores else None
    av = ""
    for e in vuln.get("severity", []):
        m = re.search(r"/AV:([NALP])", e.get("score", ""))
        if m and (not av or "NALP".index(m.group(1)) < "NALP".index(av)):
            av = m.group(1)

    vendor = None
    for e in vuln.get("severity", []):
        if e.get("type") == "Ubuntu":
            vendor = e.get("score")
    if affected:
        urgency = (affected.get("ecosystem_specific") or {}).get("urgency")
        if urgency and urgency in _VENDOR_MAP:
            vendor = urgency
    summary = vuln.get("summary", "")
    if not vendor and ":" in summary:
        head = summary.split(":", 1)[0].strip()
        if head.lower() in _VENDOR_MAP:
            vendor = head

    if vendor and vendor.lower() in _VENDOR_MAP:
        level = _VENDOR_MAP[vendor.lower()]
    elif cvss is not None:
        level = _cvss_level(cvss)
    else:
        level = "unknown"
    return Severity(level, cvss, vendor, av)
