"""cve-watch: which known vulnerabilities actually matter for your servers' configuration."""

import argparse
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from rich.console import Console

from aiops.agents.cve_watch.assess import Assessor
from aiops.agents.cve_watch.findings import collect_groups
from aiops.agents.cve_watch.hostfacts import HostFacts, parse_collector_output, parse_package_list
from aiops.agents.cve_watch.osv import OSVClient
from aiops.agents.cve_watch.report import (print_live, print_overflow, print_summary, report_path, rows_of,
                                           write_markdown)
from aiops.agents.cve_watch.severity import LEVELS
from aiops.agents.cve_watch.state import AssessmentCache
from aiops.core.ansible_runner import run_playbook, single_host_inventory
from aiops.core.config import load_settings
from aiops.core.llm import AnthropicProvider, OllamaProvider
from aiops.core.masking import Masker

PLAYBOOK = Path(__file__).parent / "ansible" / "collect.yml"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cve-watch",
        description="Read-only CVE watch: collects installed packages and runtime usage, matches them against "
                    "OSV.dev and lets an LLM judge whether each vulnerability affects your configuration.",
    )
    src = p.add_argument_group("targets (pick one)")
    src.add_argument("-i", "--inventory", help="Ansible inventory (file, dir or 'host1,host2,')")
    src.add_argument("--host", action="append", metavar="[USER@]HOST[:PORT]", help="single server (repeatable)")
    src.add_argument("--facts-dir", type=Path, help="re-use collector output saved earlier with --save-facts")
    src.add_argument("--packages", type=Path, help="manual list, one 'name version' per line (needs --ecosystem)")
    src.add_argument("--ecosystem", help="OSV ecosystem for --packages, e.g. 'Debian:12', 'Ubuntu:24.04:LTS', 'AlmaLinux:9'")
    src.add_argument("-l", "--limit", help="ansible --limit pattern")
    src.add_argument("-b", "--become", action="store_true", help="run the collector via sudo (recommended: full process/socket view)")
    src.add_argument("--save-facts", type=Path, help="keep raw collector output in this directory")

    an = p.add_argument_group("assessment")
    an.add_argument("--provider", choices=["hybrid", "anthropic", "ollama", "none"], default="hybrid",
                    help="hybrid (default): local model triages, Claude decides the rest")
    an.add_argument("--min-severity", choices=LEVELS, default="high", help="ignore vulns below this (default: high)")
    an.add_argument("--include-unknown", action="store_true",
                    help="also assess vulns without any severity rating (distro or CVSS)")
    an.add_argument("--include-inactive-kernels", action="store_true", help="also assess installed-but-not-booted kernels")
    an.add_argument("--scope", choices=["used", "all"], default="used",
                    help="used (default): only packages loaded by running processes + booted kernel; "
                         "all: also installed-only packages")
    an.add_argument("--no-kernel", action="store_true", help="skip the booted kernel")
    an.add_argument("--fresh", action="store_true", help="ignore remembered assessments and re-assess everything")
    an.add_argument("--max-per-package", type=int, default=8,
                    help="assess at most N most important vulns per package; the rest are summarized (default: 8)")
    an.add_argument("--claude-budget", type=int, default=30, help="max Claude requests per run (default: 30)")
    an.add_argument("--claude-model", help="override ANTHROPIC_MODEL")
    an.add_argument("--ollama-model", help="override OLLAMA_MODEL")
    an.add_argument("--no-mask", action="store_true", help="send IPs/hostnames to Claude unmasked")
    an.add_argument("--lang", help="language for explanations (default AIOPS_LANG or 'bg')")
    an.add_argument("--report-dir", type=Path, help="where to write the Markdown report")
    return p


def collect(args, console: Console) -> tuple[list[HostFacts], list[str]]:
    warnings: list[str] = []
    if args.packages:
        if not args.ecosystem:
            sys.exit("--packages needs --ecosystem")
        return [parse_package_list(args.packages.stem, args.packages.read_text(), args.ecosystem)], warnings

    if args.facts_dir:
        facts_dir = args.facts_dir
    else:
        if not (args.inventory or args.host):
            sys.exit("give targets: -i INVENTORY, --host HOST, --facts-dir DIR or --packages FILE")
        inventory = args.inventory or str(single_host_inventory(args.host))
        facts_dir = args.save_facts or Path(tempfile.mkdtemp(prefix="cve-watch-facts-"))
        facts_dir.mkdir(parents=True, exist_ok=True)
        console.rule("[bold]1/3 Събиране (read-only, ansible raw)")
        res = run_playbook(PLAYBOOK, inventory, {"out_dir": str(facts_dir.resolve())}, args.become, args.limit,
                           echo=lambda l: console.print(f"[dim]{l}[/]", highlight=False) if l.strip() else None)
        for h, why in res.failed_hosts.items():
            warnings.append(f"{h}: {why} — пропуснат")
        if res.returncode not in (0, 2, 4):
            sys.exit(f"ansible-playbook exited with {res.returncode}")

    hosts = []
    for f in sorted(facts_dir.glob("*.txt")):
        hf = parse_collector_output(f.stem, f.read_text(errors="replace"))
        warnings += [f"{hf.host}: {e}" for e in hf.errors]
        if hf.ecosystem_note:
            warnings.append(f"{hf.host}: {hf.ecosystem_note}")
        if not hf.ecosystem:
            warnings.append(f"{hf.host}: пропуснат (неподдържана ОС)")
            continue
        hosts.append(hf)
    return hosts, warnings


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    settings = load_settings()
    console = Console()
    lang = args.lang or settings.lang

    hosts, warnings = collect(args, console)
    if not hosts:
        console.print("[red]Няма хостове с използваеми данни.[/]")
        for w in warnings:
            console.print(f"[yellow]! {w}[/]")
        return 1
    for hf in hosts:
        console.print(f"[green]✓[/] {hf.host}: {hf.os_pretty or hf.ecosystem}, kernel {hf.kernel or '?'}, "
                      f"{len(hf.components)} пакета, {len(hf.sockets)} слушащи сокета"
                      + ("" if hf.is_root else " [yellow](без root)[/]"))

    masker = Masker(enabled=not args.no_mask)
    masker.add_hostnames(h.host for h in hosts)
    ollama = claude = None
    if args.provider in ("hybrid", "ollama"):
        ollama = OllamaProvider(settings.ollama_host, args.ollama_model or settings.ollama_model)
        ok, why = ollama.available()
        if not ok:
            console.print(f"[red]Ollama: {why}[/]")
            return 1
    if args.provider in ("hybrid", "anthropic"):
        claude = AnthropicProvider(args.claude_model or settings.anthropic_model, settings.anthropic_effort,
                                   masker, max_calls=args.claude_budget)
        ok, why = claude.available()
        if not ok:
            console.print(f"[red]Anthropic: {why}[/]")
            return 1

    console.rule("[bold]2/3 Съпоставяне с OSV.dev")
    osv = OSVClient(settings.cache_dir)
    with console.status("OSV...") as st:
        groups, stats = collect_groups(hosts, osv, LEVELS.index(args.min_severity) + 1, args.include_unknown,
                                       args.include_inactive_kernels, args.max_per_package, args.scope,
                                       not args.no_kernel, status=lambda msg: st.update(msg))
    if stats["skipped_kernels"]:
        console.print(f"[yellow]Kernel не е проверен ({'; '.join(stats['skipped_kernels'])}) — пуснато с --no-kernel[/]")
    if stats["skipped_unused"]:
        console.print(f"[dim]{stats['skipped_unused']} пакета са само инсталирани (не ги ползва работещ процес) — "
                      f"пропуснати; --scope all за пълна проверка[/]")
    console.print(f"{stats['components']} уникални пакета → {stats['matched_vulns']} известни уязвимости → "
                  f"{stats['after_filter']} с severity ≥ {args.min_severity} → {stats['to_assess']} за оценка "
                  f"(до {args.max_per_package} на пакет) в {len(groups)} групи "
                  f"[dim](OSV: изтеглени {stats['osv_fetched']} нови/променени записа)[/]")

    console.rule(f"[bold]3/3 Оценка ({args.provider})")
    done = []

    def on_done(g):
        done.append(g)
        print_live(console, g)

    assessor = Assessor(args.provider, lang, ollama, claude, on_done)
    mode_label = {"hybrid": f"hybrid:{ollama and ollama.model}>{claude and claude.model}",
                  "anthropic": f"anthropic:{claude and claude.model}",
                  "ollama": f"ollama:{ollama and ollama.model}", "none": "none"}[args.provider]
    cache = AssessmentCache(settings.cache_dir / "assessments.json", mode_label, lang)
    if not args.fresh:
        assessor.cache = cache
    try:
        with console.status("Оценка...") as st:
            assessor.status = st.update
            assessor.run(groups)
    except KeyboardInterrupt:
        warnings.append("прекъснато от потребителя — отчетът е частичен")
        console.print("[yellow]Прекъснато — записвам частичен отчет.[/]")
    finally:
        if assessor.cache:
            cache.save()
    if assessor.reused:
        console.print(f"[dim]{assessor.reused} уязвимости вече са оценени при предишно пускане — показани са само "
                      f"новите (--fresh за пълна преоценка)[/]")

    rows = [r for g in done for r in rows_of(g)]
    warnings += assessor.errors
    if assessor.budget_skipped:
        warnings.append(f"Claude бюджетът (--claude-budget {args.claude_budget}) свърши: "
                        f"{assessor.budget_skipped} уязвимости остават с оценката на локалния модел/без оценка")

    mode = {"hybrid": f"hybrid ({ollama.model if ollama else '-'} → {claude.model if claude else '-'})",
            "anthropic": f"anthropic ({claude.model if claude else '-'})",
            "ollama": f"ollama ({ollama.model if ollama else '-'})", "none": "без LLM (само правила)"}[args.provider]
    summary = {
        "Хостове": ", ".join(h.host for h in hosts),
        "Режим": mode,
        "Праг": f"severity ≥ {args.min_severity}" + (" (+ без рейтинг)" if args.include_unknown else ""),
        "Обхват": "само използвани пакети" if args.scope == "used"
                  else "всички инсталирани пакети",
        "Статистика": f"{stats['components']} пакета, {stats['matched_vulns']} съвпадения в OSV, "
                      f"{stats['after_filter']} над прага, {stats['to_assess']} оценени индивидуално "
                      f"({stats['to_assess'] - assessor.reused} нови)",
    }
    if claude and claude.usage.calls:
        cost = claude.estimated_cost()
        summary["Claude"] = (f"{claude.usage.calls} заявки, {claude.usage.input_tokens} in / "
                             f"{claude.usage.output_tokens} out токена"
                             + (f", ~${cost:.3f}" if cost is not None else ""))
    if ollama and ollama.usage.calls:
        summary["Локален модел"] = f"{ollama.usage.calls} заявки (безплатно)"

    console.rule("[bold]Резултат")
    print_summary(console, rows)
    for k, v in summary.items():
        console.print(f"[bold]{k}:[/] {v}")
    for w in warnings:
        console.print(f"[yellow]! {w}[/]")
    print_overflow(console, done)
    path = write_markdown(report_path(args.report_dir or settings.report_dir), rows, done,
                          {"date": f"{datetime.now():%Y-%m-%d %H:%M}", "summary": summary, "warnings": warnings})
    console.print(f"\nОтчет: [bold]{path}[/]")
    return 0
