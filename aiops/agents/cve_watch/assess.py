"""LLM assessment: does a version-matched vulnerability actually affect this configuration?

Modes:
  none      - rules only (severity + usage), no LLM
  ollama    - local model gives the final verdict
  anthropic - Claude gives the final verdict for every candidate
  openai    - OpenAI gives the final verdict for every candidate
  hybrid    - local model triages everything; the cloud model (Claude or OpenAI) re-assesses only what triage
              did not rule out
"""

import json
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Callable

from aiops.agents.cve_watch.findings import VERDICTS, Assessment, Group, Vuln
from aiops.agents.cve_watch.state import AssessmentCache
from aiops.core.llm import LLMError, OllamaProvider

LANG_NAMES = {"bg": "Bulgarian (български език, Cyrillic script)", "en": "English"}
DETAILS_CHARS = 1500

_SYSTEM = """You are a senior Linux security engineer triaging vulnerability scanner output for specific servers.
OSV matched each vulnerability to the exact installed package version, so the vulnerable code IS installed.
Your job is to decide whether each vulnerability actually matters for THIS host's configuration, using only the
host facts and the vulnerability text you are given.

Host fact `usage` values:
- network-exposed: the package's binaries/libraries are loaded by a process listening on a non-loopback address
- kernel-running: this is the booted kernel (check loaded_kernel_modules for the affected subsystem)
- local-listener: loaded by a process listening only on loopback
- running: loaded by a running process that does not listen on the network
- installed: on disk, not loaded by any running process (CLI tools may still be run by users/cron on untrusted input)
- unknown: no runtime data was collected

Verdicts:
- affected: vulnerable code is installed and reachable in this configuration
- likely: probably reachable; a precondition cannot be confirmed from the facts
- possible: cannot tell; depends on configuration not present in the facts
- unlikely: needs a feature or precondition the facts suggest is absent
- not_affected: the facts show the vulnerable component/feature is not in use on this host

Rules:
- Return exactly one result per vulnerability ID you were given, with the ID copied exactly.
- Do not assume facts that were not provided. If collected_as_root is false, process data is partial.
- A kernel bug in a subsystem whose module is not loaded is usually unlikely (unless it can be auto-loaded by an unprivileged user).
- Keep `reason` to at most two sentences, concrete to this host."""

_FULL_RULES = """
- exploitability: the attacker position the vulnerability needs (remote / adjacent / local / physical / unknown).
- action: concrete remediation, e.g. upgrade to the fixed version with apt/dnf, or a mitigation.
- verify: ONE read-only shell command an admin can run on the host to confirm the deciding precondition.
  It must never change state (no install/upgrade/restart/write/kill/rm)."""


def _schema(full: bool) -> dict:
    props = {
        "id": {"type": "string"},
        "verdict": {"type": "string", "enum": VERDICTS},
        "reason": {"type": "string"},
    }
    if full:
        props["exploitability"] = {"type": "string", "enum": ["remote", "adjacent", "local", "physical", "unknown"]}
        props["action"] = {"type": "string"}
        props["verify"] = {"type": "string"}
    item = {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}
    return {
        "type": "object",
        "properties": {"results": {"type": "array", "items": item}},
        "required": ["results"],
        "additionalProperties": False,
    }


def _system(full: bool, lang: str) -> str:
    s = _SYSTEM + (_FULL_RULES if full else "")
    return s + f"\n\nWrite `reason`{', `action`' if full else ''} in {LANG_NAMES.get(lang, lang)}."


def _vuln_block(v: Vuln) -> str:
    details = v.details.strip()
    if len(details) > DETAILS_CHARS:
        details = details[:DETAILS_CHARS] + " [...]"
    head = f"### ID: {v.id}\nCVEs: {', '.join(v.cves) or '-'} | severity: {v.severity.label()} | fixed in: {', '.join(v.fixed) or 'no fix yet'} | published: {v.published or '?'}"
    return f"{head}\nSummary: {v.summary or '-'}\nDetails: {details or '-'}"


def _user_prompt(g: Group, vulns: list[Vuln], lang: str) -> str:
    c = g.component
    return "\n".join([
        f"## Host context (identical on {len(g.hosts)} host(s))",
        json.dumps(g.context, indent=1, ensure_ascii=False),
        "",
        "## Package",
        f"ecosystem: {c.ecosystem}",
        f"package: {c.name}  installed version: {c.version}",
        f"binary packages from it installed: {', '.join(c.binaries[:30])}",
        "",
        "## Vulnerabilities (version-matched by OSV)",
        *(_vuln_block(v) for v in vulns),
        "",
        f"Return one result per ID above. Write the free-text fields in {LANG_NAMES.get(lang, lang)}.",
    ])


def _chunks(items, n):
    for i in range(0, len(items), n):
        yield items[i : i + n]


class Assessor:
    def __init__(self, mode: str, lang: str, ollama: OllamaProvider | None, cloud,
                 on_group_done: Callable[[Group], None], batch_size: int = 6, cloud_workers: int = 4):
        self.mode = mode
        self.lang = lang
        self.ollama = ollama
        self.cloud = cloud  # AnthropicProvider | OpenAIProvider
        self.on_group_done = on_group_done
        self.batch_size = batch_size
        self.cloud_workers = cloud_workers
        self.errors: list[str] = []
        self.budget_skipped = 0
        self.status: Callable[[str], None] = lambda msg: None
        self.cache: AssessmentCache | None = None
        self.reused = 0

    def _ask(self, provider, g: Group, vulns: list[Vuln], full: bool, by: str) -> dict[str, Assessment]:
        out = {}
        for chunk in _chunks(vulns, self.batch_size):
            if provider is self.ollama:
                self.status(f"{provider.model}: оценявам {g.component.name} ({len(chunk)} уязвимости)...")
            try:
                data = provider.complete_json(_system(full, self.lang), _user_prompt(g, chunk, self.lang), _schema(full))
            except LLMError as e:
                self.errors.append(f"{g.component.name}: {e}")
                for v in chunk:
                    out[v.id] = Assessment("unassessed", reason=str(e), by=by)
                continue
            wanted = {v.id for v in chunk}
            for r in data.get("results", []):
                if isinstance(r, dict) and r.get("id") in wanted:
                    verdict = r.get("verdict")
                    out[r["id"]] = Assessment(
                        verdict=verdict if verdict in VERDICTS else "possible",
                        exploitability=r.get("exploitability", "unknown"),
                        reason=r.get("reason", ""),
                        action=r.get("action", ""),
                        verify=r.get("verify", ""),
                        by=by,
                    )
            for v in chunk:
                out.setdefault(v.id, Assessment("unassessed", reason="model returned no result for this ID", by=by))
        return out

    def _final_cloud(self, g: Group, vulns: list[Vuln], prior: dict[str, Assessment]) -> Group:
        for chunk in _chunks(vulns, self.batch_size):
            if self.cloud.try_reserve_call():
                g.assessments.update(self._ask(self.cloud, g, chunk, True, f"{self.cloud.name} ({self.cloud.model})"))
                continue
            self.budget_skipped += len(chunk)
            for v in chunk:
                a = prior.get(v.id) or Assessment("unassessed")
                a.by = (a.by + ", " if a.by else "") + "cloud budget exhausted"
                g.assessments[v.id] = a
        return g

    def _from_cache(self, g: Group) -> list[Vuln]:
        """Fill remembered verdicts into the group; return the vulns that still need a model."""
        todo = []
        for v in g.vulns:
            a = self.cache.get(g, v) if self.cache else None
            if a:
                g.assessments[v.id] = a
            else:
                todo.append(v)
        return todo

    def _done(self, g: Group, todo: list[Vuln]):
        if self.cache:
            for v in todo:
                if v.id in g.assessments:
                    self.cache.put(g, v, g.assessments[v.id])
        self.on_group_done(g)

    def run(self, groups: list[Group]):
        if self.mode == "none":
            for g in groups:
                g.assessments = {v.id: Assessment("unassessed", by="rules") for v in g.vulns}
                self.on_group_done(g)
            return
        todos = {id(g): self._from_cache(g) for g in groups}
        self.reused = sum(len(g.vulns) - len(todos[id(g)]) for g in groups)
        if self.mode == "ollama":
            for g in groups:
                todo = todos[id(g)]
                if todo:
                    g.assessments.update(self._ask(self.ollama, g, todo, True, f"ollama ({self.ollama.model})"))
                self._done(g, todo)
            return

        with ThreadPoolExecutor(self.cloud_workers) as ex:
            futures: dict[Future, list[Vuln]] = {}
            for g in groups:
                todo = todos[id(g)]
                if not todo:
                    self._done(g, todo)
                    continue
                if self.mode in ("anthropic", "openai"):
                    futures[ex.submit(self._final_cloud, g, todo, {})] = todo
                    continue
                # hybrid: cheap local triage first; only what it does not rule out goes to the cloud model.
                triage = self._ask(self.ollama, g, todo, False, f"ollama ({self.ollama.model})")
                g.assessments.update({k: a for k, a in triage.items() if a.verdict in ("unlikely", "not_affected")})
                escalate = [v for v in todo if v.id not in g.assessments]
                if not escalate:
                    self._done(g, todo)
                    continue
                futures[ex.submit(self._final_cloud, g, escalate, triage)] = todo
                # Report whatever the cloud model finished while the local model was busy.
                for f in [f for f in futures if f.done()]:
                    self._done(f.result(), futures.pop(f))
            for f in as_completed(list(futures)):
                self._done(f.result(), futures[f])
