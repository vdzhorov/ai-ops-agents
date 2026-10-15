"""changelog: available versions, latest releases, and everything that changed between two versions."""

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.table import Table

from aiops.agents.changelog.model import find, latest, select_range, sort_releases, version_key
from aiops.agents.changelog.sources import resolve_source
from aiops.agents.changelog.summarize import CATEGORIES, Digest, summarize
from aiops.core.config import load_settings
from aiops.core.llm import AnthropicProvider, OllamaProvider
from aiops.core.masking import Masker
from aiops.core.webcache import FetchError, WebCache

RISK_STYLE = {"low": "green", "medium": "yellow", "high": "bold red"}


def _flags(item: dict, rich: bool) -> str:
    flags = []
    if item.get("unclear"):
        flags.append("неясно в източника — виж пълния текст")
    if item.get("verified") is False:
        flags.append("цитатът НЕ е открит в release notes — провери")
    if not flags:
        return ""
    text = " [" + "; ".join(flags) + "]"
    return f" [yellow]{escape(text)}[/]" if rich else text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="changelog", description="Versions and changelogs of software.")
    sub = p.add_subparsers(dest="cmd", required=True)
    soft_help = "jumpserver | comet | openstack (series) | nova, neutron, ... (OpenStack projects) | github:<owner>/<repo>"

    v = sub.add_parser("versions", help="list available versions (newest first)")
    v.add_argument("software", help=soft_help)
    v.add_argument("-n", "--limit", type=int, default=10, help="how many newest versions to show (default 10)")
    v.add_argument("--all", action="store_true", help="show all versions")
    v.add_argument("--line", help="only this release line / track / series")
    v.add_argument("--pre", action="store_true", help="include pre-releases (rc, beta, ...)")

    lt = sub.add_parser("latest", help="newest release overall and per release line")
    lt.add_argument("software", help=soft_help)
    lt.add_argument("--pre", action="store_true")

    d = sub.add_parser(
        "diff",
        help="all changes between two versions, including every version in between",
        usage="%(prog)s SOFTWARE FROM_VERSION [TO_VERSION] [options]",
        description="All changes after FROM_VERSION up to and including TO_VERSION, including every version "
                    "in between. Without TO_VERSION: up to the latest release.",
        epilog="""examples:
  changelog diff jumpserver v4.10.15 v5.0.0     # v4.10.16, ..., v4.10.19, v5.0.0
  changelog diff jumpserver v4.10.15            # from v4.10.15 to the latest release
  changelog diff comet 26.8.5 26.8.9            # 26.8.6, 26.8.7, 26.8.8, 26.8.9
  changelog diff openstack 2024.1 2025.2        # release highlights of 2024.2, 2025.1, 2025.2
  changelog diff nova caracal epoxy             # OpenStack project: series name = its latest version
  changelog diff jumpserver v4.10.15 v5.0.0 --provider none   # notes only, no AI digest

list the available versions first with:  changelog versions SOFTWARE""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    d.add_argument("software", metavar="SOFTWARE", help=soft_help)
    d.add_argument("from_version", metavar="FROM_VERSION",
                   help="the version you have now (its own notes are NOT included); OpenStack: series name works too")
    d.add_argument("to_version", metavar="TO_VERSION", nargs="?",
                   help="the version you upgrade to (included); default: latest release")
    d.add_argument("--pre", action="store_true", help="include pre-releases in the range")
    d.add_argument("--provider", choices=["auto", "anthropic", "ollama", "none"], default="auto",
                   help="AI digest: auto = Claude if ANTHROPIC_API_KEY is set, else local Ollama")
    d.add_argument("--raw", action="store_true", help="also print the full release notes to stdout")
    d.add_argument("--lang", help="language of the AI digest (default AIOPS_LANG or 'bg')")
    d.add_argument("--report-dir", type=Path)
    return p


def _load(args, console, web):
    src = resolve_source(args.software, web)
    with console.status(f"{src.name}: версии..."):
        rels = src.releases()
    if not rels:
        sys.exit(f"{src.name}: не са намерени версии")
    return src, rels


def cmd_versions(args, console, web):
    src, rels = _load(args, console, web)
    pool = [r for r in rels if (args.pre or not r.prerelease) and (not args.line or r.line.startswith(args.line))]
    shown = sort_releases(pool)[::-1]
    if not args.all:
        shown = shown[: args.limit]
    if src.dates_from_notes and any(not r.date for r in shown):
        with console.status("дати...") as st:
            src.fill_notes(shown, status=st.update)
    newest, per_line = latest(rels, args.pre)
    t = Table(title=f"{src.name}: {len(pool)} версии" + (f" (показани {len(shown)})" if len(shown) < len(pool) else ""))
    for col in ("Версия", "Дата", "Линия", ""):
        t.add_column(col)
    # Mark "latest in line" only where a line has several releases (OpenStack series are one per line).
    line_sizes = {}
    for r in rels:
        line_sizes[r.line] = line_sizes.get(r.line, 0) + 1
    latest_ids = {id(r) for line, r in per_line.items() if line_sizes[line] > 1}
    for r in shown:
        mark = "★ последна" if r is newest else ("последна в линията" if id(r) in latest_ids else "")
        if r.prerelease:
            mark = (mark + " pre-release").strip()
        t.add_row(escape(r.version), r.date, escape(r.line), mark)
    console.print(t)


def cmd_latest(args, console, web):
    src, rels = _load(args, console, web)
    newest, per_line = latest(rels, args.pre)
    lines = sorted(per_line.values(), key=lambda r: r.key, reverse=True)[:15]
    if src.dates_from_notes:
        with console.status("дати...") as st:
            src.fill_notes(lines, status=st.update)
    console.print(f"[bold]{src.name}[/] — последна версия: [bold green]{escape(newest.version)}[/]"
                  + (f" ({newest.date})" if newest.date else ""))
    t = Table(title="Последна версия по линия")
    for col in ("Линия", "Версия", "Дата"):
        t.add_column(col)
    for r in lines:
        t.add_row(escape(r.line), escape(r.version), r.date)
    console.print(t)


def _provider(choice: str, settings, console):
    if choice == "none":
        return None
    if choice in ("anthropic", "auto") and (os.getenv("ANTHROPIC_API_KEY") or choice == "anthropic"):
        p = AnthropicProvider(settings.anthropic_model, settings.anthropic_effort, Masker(enabled=False))
        ok, why = p.available()
        if ok:
            return p
        console.print(f"[yellow]Anthropic: {why}[/]")
        if choice == "anthropic":
            return None
    p = OllamaProvider(settings.ollama_host, settings.ollama_model, num_ctx=16384)
    ok, why = p.available()
    if not ok:
        console.print(f"[yellow]Ollama: {why} — без AI обобщение[/]")
        return None
    return p


def _print_digest(console, d: Digest):
    if d.summary:
        console.print(f"\n[bold]Обобщение[/] [dim]({d.by})[/]  риск: [{RISK_STYLE.get(d.risk, '')}]{d.risk or '?'}[/]")
        console.print(escape(d.summary))
    for k, title in CATEGORIES.items():
        if d.items.get(k):
            console.print(f"\n[bold]{title}[/]")
            for i in d.items[k]:
                console.print(f"  • [cyan]{escape(i.get('version', ''))}[/] {escape(i.get('text', ''))}{_flags(i, True)}")
                if i.get("quote"):
                    console.print(f"    [dim]„{escape(i['quote'])}“[/]")
    if d.recommendations:
        console.print("\n[bold]Препоръки[/]")
        for rec in d.recommendations:
            console.print(f"  → {escape(rec)}")
    for e in d.errors:
        console.print(f"[yellow]! {escape(e)}[/]")


def _write_report(path: Path, src, from_v, to_v, rng, d: Digest | None) -> Path:
    out = [f"# {src.name}: {from_v} → {to_v}", "",
           f"- **Версии в интервала ({len(rng)}):** {', '.join(r.version for r in rng)}",
           f"- **Генериран:** {datetime.now():%Y-%m-%d %H:%M}", ""]
    if d and (d.summary or any(d.items.values())):
        out += [f"## AI обобщение ({d.by})", "",
                "_Генерирано от AI. Всяка точка има дословен цитат от източника; пълният текст е по-долу._", "",
                f"**Риск:** {d.risk or '?'}", "", d.summary, ""]
        for k, title in CATEGORIES.items():
            if d.items.get(k):
                out += [f"### {title}", ""]
                for i in d.items[k]:
                    out.append(f"- **{i.get('version', '')}** {i.get('text', '')}{_flags(i, False)}")
                    if i.get("quote"):
                        out.append(f"  > {i['quote']}")
                out.append("")
        if d.recommendations:
            out += ["### Препоръки", ""] + [f"- {x}" for x in d.recommendations] + [""]
    out += ["## Пълни release notes (от най-старата към най-новата)", ""]
    for r in rng:
        head = f"### {r.version}" + (f" — {r.date}" if r.date else "") + (f" · {r.line}" if r.line else "")
        notes = re.sub(r"^(#{1,3}) ", lambda m: "#" * (len(m.group(1)) + 3) + " ", r.notes or "", flags=re.M)
        out += [head, "", (f"<{r.url}>\n\n" if r.url else "") + notes, ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out), encoding="utf-8")
    return path


def cmd_diff(args, console, web, settings):
    src, rels = _load(args, console, web)
    newest, _ = latest(rels, args.pre)
    from_v = src.resolve(args.from_version, rels)
    to_v = src.resolve(args.to_version, rels) if args.to_version else newest.version
    for label, v in (("from", from_v), ("to", to_v)):
        if find(rels, v):
            continue
        if not version_key(v)[0]:  # not a version number at all (e.g. a typo or a sub-command name)
            raise ValueError(f"'{v}' не е версия на {src.name}. Списък с версиите: "
                             f"python -m aiops changelog versions {args.software}")
        console.print(f"[yellow]! {label} версия '{v}' не е сред публикуваните — интервалът е по номер на версия[/]")
    rng = select_range(rels, from_v, to_v, args.pre)
    if not rng:
        console.print(f"Няма версии между {from_v} и {to_v}.")
        return
    with console.status("release notes...") as st:
        src.fill_notes(rng, status=st.update)

    t = Table(title=f"{src.name}: {from_v} → {to_v} — {len(rng)} версии (включително междинните)")
    for col in ("Версия", "Дата", "Линия", "Размер"):
        t.add_column(col)
    for r in rng:
        t.add_row(escape(r.version), r.date, escape(r.line), f"{len(r.notes or '')} зн.")
    console.print(t)
    if src.kind == "openstack" and not getattr(src, "project", ""):
        console.print("[yellow]! Release Highlights са съкратени акценти от екипите и често са двусмислени. "
                      "За точни промени по проект: changelog diff <проект> <от> <до> (напр. glance, nova).[/]")
    if args.raw:
        for r in rng:
            console.rule(f"{r.version} {r.date}")
            console.print(Markdown(r.notes or ""))

    digest = None
    provider = _provider(args.provider, settings, console)
    if provider:
        max_chars = 60000 if provider.name == "anthropic" else 16000
        with console.status("AI обобщение...") as st:
            digest = summarize(provider, src.name, from_v, to_v, rng, args.lang or settings.lang, max_chars, st.update)
        _print_digest(console, digest)

    name = re.sub(r"[^a-zA-Z0-9.-]+", "_", f"{src.name}-{from_v}-{to_v}")
    path = _write_report((args.report_dir or settings.report_dir) / f"changelog-{name}-{datetime.now():%Y%m%d-%H%M%S}.md",
                         src, from_v, to_v, rng, digest)
    console.print(f"\nОтчет (обобщение + пълни release notes): [bold]{path}[/]")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    settings = load_settings()
    console = Console()
    web = WebCache(settings.cache_dir / "web", user_agent="aiops-changelog")
    try:
        if args.cmd == "versions":
            cmd_versions(args, console, web)
        elif args.cmd == "latest":
            cmd_latest(args, console, web)
        else:
            cmd_diff(args, console, web, settings)
    except (ValueError, FetchError) as e:
        console.print(f"[red]{escape(str(e))}[/]")
        return 1
    return 0
