"""Turn host facts + OSV matches into deduplicated findings, grouped for assessment."""

from dataclasses import dataclass, field

from aiops.agents.cve_watch.hostfacts import USAGE_ORDER, Component, ComponentUsage, HostFacts
from aiops.agents.cve_watch.osv import OSVClient
from aiops.agents.cve_watch.severity import Severity, severity_of

VERDICTS = ["affected", "likely", "possible", "unlikely", "not_affected"]
IMPORTANT_VERDICTS = {"affected", "likely", "possible"}
# Bugfix / enhancement advisories from RHEL clones are not security issues.
NON_SECURITY_PREFIXES = ("ALBA-", "ALEA-", "RLBA-", "RLEA-", "RHBA-", "RHEA-")


@dataclass
class Vuln:
    id: str
    cves: list[str]
    summary: str
    details: str
    severity: Severity
    fixed: list[str]
    published: str


@dataclass
class Assessment:
    verdict: str = "unassessed"
    exploitability: str = "unknown"
    reason: str = ""
    action: str = ""
    verify: str = ""
    by: str = ""
    cached: bool = False    # True when reused from an earlier run (not new)


@dataclass
class Group:
    """Vulns of one component whose usage context is identical on every listed host."""

    component: Component
    usage: ComponentUsage
    context: dict           # host context shared by all hosts in the group (no hostnames)
    hosts: list[str]
    vulns: list[Vuln]                                         # sent for assessment
    overflow: list[Vuln] = field(default_factory=list)        # above the per-package cap, summarized only
    assessments: dict[str, Assessment] = field(default_factory=dict)

    @property
    def priority(self):
        top = max((v.severity.rank for v in self.vulns), default=0)
        return (-top, USAGE_ORDER.index(self.usage.level), self.component.name)


def _affected_entry(vuln: dict, comp: Component) -> dict | None:
    for a in vuln.get("affected", []):
        p = a.get("package", {})
        if p.get("name") == comp.name and p.get("ecosystem") == comp.ecosystem:
            return a
    return None


def _fixed_versions(affected: dict | None) -> list[str]:
    if not affected:
        return []
    out = []
    for r in affected.get("ranges", []):
        for ev in r.get("events", []):
            if "fixed" in ev and ev["fixed"] not in out:
                out.append(ev["fixed"])
    return out


def _cves(vuln: dict) -> list[str]:
    ids = [vuln["id"]] + vuln.get("upstream", []) + vuln.get("aliases", []) + vuln.get("related", [])
    return sorted({i for i in ids if i.startswith("CVE-")})


def build_vulns(comp: Component, ids: list[str], records: dict[str, dict]) -> list[Vuln]:
    """Drop withdrawn entries and duplicates (e.g. USN-x when UBUNTU-CVE-y already covers its CVEs)."""
    vulns, covered = [], set()
    # Per-CVE entries first, aggregate advisories (USN/DSA/DLA) after.
    order = sorted(ids, key=lambda i: (0 if "-CVE-" in i else 1, i))
    for vid in order:
        if vid.startswith(NON_SECURITY_PREFIXES):
            continue
        rec = records.get(vid)
        if not rec or rec.get("withdrawn"):
            continue
        cves = _cves(rec)
        if cves and set(cves) <= covered:
            continue
        covered |= set(cves)
        aff = _affected_entry(rec, comp)
        vulns.append(Vuln(
            id=vid,
            cves=cves,
            summary=rec.get("summary", ""),
            details=rec.get("details", ""),
            severity=severity_of(rec, aff),
            fixed=_fixed_versions(aff),
            published=rec.get("published", "")[:10],
        ))
    return vulns


def host_context(hf: HostFacts, comp: Component, usage: ComponentUsage) -> dict:
    ctx = {
        "os": hf.os_pretty or hf.ecosystem,
        "kernel": hf.kernel,
        "arch": hf.arch,
        "collected_as_root": hf.is_root,
        "usage": usage.level,
        "processes_using_package": usage.procs[:25],
        "listening_sockets_of_those_processes": usage.sockets[:25],
    }
    if comp.is_kernel:
        ctx["loaded_kernel_modules"] = sorted(hf.modules)
    if not hf.has_runtime:
        ctx["note"] = "only a package list was provided; runtime usage is unknown"
    return ctx


def importance(v: Vuln):
    """Sort key, most important first: severity, network attack vector, fix available, CVSS, recency."""
    av = {"N": 0, "A": 1, "L": 2, "P": 3}.get(v.severity.attack_vector, 2)
    recency = -int(v.published.replace("-", "")) if v.published[:4].isdigit() else 0
    return (-v.severity.rank, av, 0 if v.fixed else 1, -(v.severity.cvss or 0), recency)


def _rate_unscored(vulns_by_comp: dict[tuple, list[Vuln]], osv: OSVClient, status, max_cves: int = 10):
    """Distro notices (e.g. Ubuntu USN) carry no rating: take the highest CVSS of the CVEs they fix."""
    unscored = [v for vs in vulns_by_comp.values() for v in vs if v.severity.level == "unknown" and v.cves]
    cve_ids = {c: "" for v in unscored for c in v.cves[:max_cves]}
    if not cve_ids:
        return
    status(f"OSV: CVSS за {len(cve_ids)} CVE от advisories без рейтинг...")
    cve_recs = osv.get_many(cve_ids)
    for v in unscored:
        rated = [severity_of(cve_recs[c], None) for c in v.cves[:max_cves] if cve_recs.get(c)]
        rated = [s for s in rated if s.level != "unknown"]
        if rated:
            best = max(rated, key=lambda s: (s.rank, s.cvss or 0))
            v.severity = Severity(best.level, best.cvss, v.severity.vendor, best.attack_vector)


# Usage levels checked by default (--scope used); "all" adds installed-only packages.
USED_LEVELS = {"network-exposed", "kernel-running", "local-listener", "running", "unknown"}


def collect_groups(hosts: list[HostFacts], osv: OSVClient, min_rank: int, include_unknown: bool,
                   include_inactive_kernels: bool = False, per_package: int = 8, scope: str = "used",
                   include_kernel: bool = True, status=lambda msg: None) -> tuple[list[Group], dict]:
    stats = {"components": 0, "skipped_unused": 0, "skipped_kernels": [], "matched_vulns": 0, "after_filter": 0,
             "osv_fetched": 0}

    # (host, component, usage) triples in scope; usage decides both scope and grouping.
    selected = []
    for hf in hosts:
        for c in hf.components:
            if not c.ecosystem:
                continue
            usage = hf.usage(c)
            if c.is_kernel and not include_kernel:
                if usage.level == "kernel-running":
                    stats["skipped_kernels"].append(f"{hf.host}: {c.name} {c.version}")
                continue
            if usage.level == "kernel-inactive" and not include_inactive_kernels:
                continue
            if scope == "used" and usage.level not in USED_LEVELS | {"kernel-inactive"}:
                stats["skipped_unused"] += 1
                continue
            selected.append((hf, c, usage))
    comps: dict[tuple, Component] = {}
    for _, c, _ in selected:
        comps.setdefault(c.key, c)
    keys = list(comps)
    stats["components"] = len(keys)

    status(f"OSV: търся уязвимости за {len(keys)} пакета...")
    matches = dict(zip(keys, osv.match(keys, status=status)))
    wanted = {i: m for ids in matches.values() for i, m in ids.items() if not i.startswith(NON_SECURITY_PREFIXES)}
    records = osv.get_many(wanted, on_progress=lambda d, t: status(
        f"OSV: детайли за уязвимости {d}/{t} (сваля се само новото/промененото)"))
    vulns_by_comp = {k: build_vulns(comps[k], list(ids), records) for k, ids in matches.items() if ids}
    _rate_unscored(vulns_by_comp, osv, status)
    stats["osv_fetched"] = osv.fetched
    stats["matched_vulns"] = sum(len(v) for v in vulns_by_comp.values())

    def keep(v: Vuln) -> bool:
        return v.severity.rank >= min_rank or (v.severity.level == "unknown" and include_unknown)

    groups: dict[tuple, Group] = {}
    for hf, c, usage in selected:
        vulns = sorted((v for v in vulns_by_comp.get(c.key, []) if keep(v)), key=importance)
        if not vulns:
            continue
        ctx = host_context(hf, c, usage)
        sig = (c.key, repr(sorted(ctx.items())))
        if sig not in groups:
            groups[sig] = Group(c, usage, ctx, [hf.host], vulns[:per_package], vulns[per_package:])
        elif hf.host not in groups[sig].hosts:
            groups[sig].hosts.append(hf.host)
    result = sorted(groups.values(), key=lambda g: g.priority)
    stats["after_filter"] = sum(len(g.vulns) + len(g.overflow) for g in result)
    stats["to_assess"] = sum(len(g.vulns) for g in result)
    return result, stats
