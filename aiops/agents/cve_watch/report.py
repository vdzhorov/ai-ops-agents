"""Live stdout output while assessing, plus the end-of-run summary and Markdown report."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from aiops.agents.cve_watch.findings import IMPORTANT_VERDICTS, VERDICTS, Assessment, Group, Vuln

SEV_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "dim", "unknown": "magenta"}
VERDICT_STYLE = {"affected": "bold red", "likely": "red", "possible": "yellow", "unlikely": "green",
                 "not_affected": "green", "unassessed": "magenta"}


@dataclass
class Row:
    group: Group
    vuln: Vuln
    a: Assessment

    @property
    def important(self) -> bool:
        return self.a.verdict in IMPORTANT_VERDICTS or self.a.verdict == "unassessed"

    @property
    def sort_key(self):
        vi = VERDICTS.index(self.a.verdict) if self.a.verdict in VERDICTS else 2
        return (vi, -self.vuln.severity.rank, self.group.component.name, self.vuln.id)


def rows_of(g: Group) -> list[Row]:
    return [Row(g, v, g.assessments.get(v.id, Assessment())) for v in g.vulns]


def _title(v: Vuln) -> str:
    return ", ".join(v.cves[:3]) + (f" +{len(v.cves) - 3}" if len(v.cves) > 3 else "") if v.cves else v.id


def print_live(console: Console, g: Group):
    for r in sorted(rows_of(g), key=lambda r: r.sort_key):
        if not r.important or r.a.cached:
            continue
        sev = r.vuln.severity.level
        c = g.component
        console.print(
            f"[{SEV_STYLE[sev]}]{sev.upper():>8}[/] "
            f"[{VERDICT_STYLE.get(r.a.verdict, '')}]{r.a.verdict:<12}[/] "
            f"[bold]{escape(_title(r.vuln))}[/]  {escape(c.name)} {escape(c.version)}  "
            f"[cyan]{escape(', '.join(g.hosts))}[/] [dim]({g.usage.level})[/]"
        )
        if r.a.reason:
            console.print(f"           [dim]↳ {escape(r.a.reason)}[/]")


def print_summary(console: Console, rows: list[Row]):
    important = sorted([r for r in rows if r.important], key=lambda r: r.sort_key)
    if not important:
        console.print("\n[bold green]Няма уязвимости, които да засягат конфигурацията (според зададения праг).[/]")
        return
    t = Table(title=f"Важни уязвимости ({len(important)})", show_lines=True, expand=True)
    for col in ("Severity", "Оценка", "CVE / ID", "Пакет", "Хостове", "Защо / действие"):
        t.add_column(col, overflow="fold")
    for r in important:
        c = r.group.component
        t.add_row(
            f"[{SEV_STYLE[r.vuln.severity.level]}]{r.vuln.severity.level.upper()}[/]",
            f"[{VERDICT_STYLE.get(r.a.verdict, '')}]{r.a.verdict}[/]\n[dim]{r.a.exploitability}[/]",
            escape(_title(r.vuln)) + ("" if r.a.cached else "\n[bold cyan]★ НОВО[/]"),
            f"{escape(c.name)} {escape(c.version)}\n[dim]fix: {escape(', '.join(r.vuln.fixed) or 'няма')}[/]",
            escape(", ".join(r.group.hosts)),
            escape(r.a.reason) + (f"\n[bold]→[/] {escape(r.a.action)}" if r.a.action else ""),
        )
    console.print(t)


def _overflow_line(g: Group) -> str:
    counts = Counter(v.severity.level for v in g.overflow)
    parts = ", ".join(f"{counts[l]} {l}" for l in ("critical", "high", "unknown", "medium", "low") if counts[l])
    no_fix = sum(1 for v in g.overflow if not v.fixed)
    c = g.component
    return (f"{c.name} {c.version} ({g.usage.level}) на {', '.join(g.hosts)}: още {len(g.overflow)} неоценени "
            f"({parts}; {no_fix} без поправка) — повечето се затварят със същия ъпдейт на пакета")


def print_overflow(console: Console, groups: list[Group]):
    for g in groups:
        if g.overflow:
            console.print(f"[dim]+ {escape(_overflow_line(g))}[/]")


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def write_markdown(path: Path, rows: list[Row], groups: list[Group], meta: dict) -> Path:
    important = sorted([r for r in rows if r.important], key=lambda r: r.sort_key)
    dismissed = sorted([r for r in rows if not r.important], key=lambda r: r.sort_key)
    out = [f"# CVE Watch отчет — {meta['date']}", ""]
    for k, v in meta["summary"].items():
        out.append(f"- **{k}:** {v}")
    out += ["", f"## Важни ({len(important)})", ""]
    if not important:
        out.append("_Няма уязвимости, които да засягат конфигурацията (според зададения праг)._")
    for r in important:
        v, c, g, a = r.vuln, r.group.component, r.group, r.a
        out += [
            f"### [{v.severity.level.upper()}] {_title(v)} — {c.name} {c.version}" + ("" if a.cached else " ★ НОВО"),
            "",
            f"- **Оценка:** `{a.verdict}` · експлоатация: {a.exploitability} · от: {a.by}",
            f"- **Severity:** {v.severity.label()}",
            f"- **Хостове:** {', '.join(g.hosts)}",
            f"- **Употреба:** {g.usage.level}"
            + (f" — процеси: {', '.join(g.usage.procs[:10])}" if g.usage.procs else "")
            + (f"; сокети: {', '.join(g.usage.sockets[:5])}" if g.usage.sockets else ""),
            f"- **Поправено във:** {', '.join(v.fixed) or 'няма поправка още'} ({c.ecosystem})",
        ]
        if a.reason:
            out.append(f"- **Защо:** {a.reason}")
        if a.action:
            out.append(f"- **Действие:** {a.action}")
        if a.verify:
            out.append(f"- **Проверка (read-only):** `{a.verify}`")
        out += [f"- **Източник:** [{v.id}](https://osv.dev/vulnerability/{v.id}) — {v.summary}".rstrip(" —"), ""]
    overflow = [g for g in groups if g.overflow]
    if overflow:
        out += ["## Над лимита за пакет (неоценени индивидуално)", ""]
        out += [f"- {_overflow_line(g)}" for g in overflow] + [""]
    if dismissed:
        out += [f"## Отхвърлени като нерелевантни ({len(dismissed)})", "",
                "| Severity | ID | Пакет | Оценка | Хостове | Защо |", "|---|---|---|---|---|---|"]
        for r in dismissed:
            out.append("| " + " | ".join(_md_cell(x) for x in (
                r.vuln.severity.level, _title(r.vuln), f"{r.group.component.name} {r.group.component.version}",
                r.a.verdict, ", ".join(r.group.hosts), r.a.reason)) + " |")
        out.append("")
    if meta.get("warnings"):
        out += ["## Предупреждения", ""] + [f"- {w}" for w in meta["warnings"]] + [""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out), encoding="utf-8")
    return path


def report_path(report_dir: Path) -> Path:
    return report_dir / f"cve-watch-{datetime.now():%Y%m%d-%H%M%S}.md"
