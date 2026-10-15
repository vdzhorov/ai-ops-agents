"""LLM digest of all release notes in a version range: what an operator must know before upgrading.

Large ranges are processed map/reduce: each chunk of notes -> extracted items, then one call writes the summary."""

import json
import re
from dataclasses import dataclass, field

from aiops.agents.changelog.model import Release
from aiops.core.llm import LLMError

CATEGORIES = {
    "breaking": "Breaking changes / несъвместимости",
    "security": "Security",
    "upgrade_notes": "Бележки за ъпгрейд (миграции, ръчни стъпки)",
    "deprecations": "Deprecations / премахнати неща",
    "features": "Нови възможности",
    "notable_fixes": "Важни поправки",
}
LANG_NAMES = {"bg": "Bulgarian (български език, Cyrillic script)", "en": "English"}

_ITEM = {
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "text": {"type": "string"},
        "quote": {"type": "string"},
        "unclear": {"type": "boolean"},
    },
    "required": ["version", "text", "quote", "unclear"],
    "additionalProperties": False,
}
_ITEMS_PROPS = {k: {"type": "array", "items": _ITEM} for k in CATEGORIES}
_SUMMARY_PROPS = {
    "summary": {"type": "string"},
    "risk": {"type": "string", "enum": ["low", "medium", "high"]},
    "recommendations": {"type": "array", "items": {"type": "string"}},
}


def _schema(props: dict) -> dict:
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


_SYSTEM = """You are a senior operations engineer preparing an upgrade of {software} from {from_v} to {to_v}.
You get the release notes of EVERY version in between (oldest first). Extract what an operator must know.

Categories:
- breaking: incompatible changes, changed defaults, removed or renamed options/APIs/CLI flags
- security: security fixes and CVEs
- upgrade_notes: required manual steps, migrations, ordering constraints, minimum versions of dependencies
- deprecations: features deprecated or removed
- features: notable new features (skip minor UI tweaks)
- notable_fixes: bug fixes likely to matter in production (data loss, crashes, performance); skip trivial ones

Rules:
- Use only what the notes say. Every item names the version it comes from.
- quote: copy the exact source sentence or fragment the item is based on, verbatim and in its original language
  (max ~200 characters). Never paraphrase or translate the quote.
- Do not fill gaps with assumptions. If a note is terse or ambiguous (e.g. "Removed Windows OS support" does not
  say whether it means running the service on Windows or Windows guests), restate only what is certain, set
  unclear=true and say in `text` what is ambiguous. Never guess the missing meaning.
- Merge duplicates (same change mentioned in several versions -> one item, earliest version).
- Be concise: one sentence per item. Notes may be in any language; write `text` in {lang}."""

_REDUCE = """You get the extracted change items for the whole range. Write:
- summary: 3-6 sentences on what this upgrade means in practice
- risk: low / medium / high for performing this upgrade
- recommendations: concrete steps before/after upgrading (backups, config changes, checks)
Base every statement only on the items. Do not recommend anything for items marked unclear except
"read the full release notes of <project/version>". Write in {lang}."""


@dataclass
class Digest:
    items: dict[str, list[dict]] = field(default_factory=lambda: {k: [] for k in CATEGORIES})
    summary: str = ""
    risk: str = ""
    recommendations: list[str] = field(default_factory=list)
    by: str = ""
    errors: list[str] = field(default_factory=list)


def _norm(t: str) -> str:
    t = re.sub(r"[`*_“”\"'’‘]", "", t.lower())
    return re.sub(r"\s+", " ", t).strip()


def _verify_quotes(d: Digest, rels: list[Release]):
    """Mark items whose quote does not occur in the source notes (the model invented or rewrote it)."""
    by_version = {_norm(r.version.lstrip("vV")): _norm(r.notes or "") for r in rels}
    everything = " ".join(by_version.values())
    for items in d.items.values():
        for i in items:
            q = _norm(i.get("quote", "")).rstrip(".… ")
            if not q:
                i["verified"] = False
                continue
            source = by_version.get(_norm(i.get("version", "").lstrip("vV")), everything)
            i["verified"] = q in source or q in everything


def _chunks(rels: list[Release], max_chars: int) -> list[str]:
    chunks, cur = [], ""
    for r in rels:
        block = f"\n\n===== {r.version} ({r.date or 'дата неизв.'}) =====\n{(r.notes or '').strip()}"
        if len(block) > max_chars:
            block = block[:max_chars] + "\n[... съкратено]"
        if cur and len(cur) + len(block) > max_chars:
            chunks.append(cur)
            cur = ""
        cur += block
    if cur:
        chunks.append(cur)
    return chunks


def summarize(provider, software: str, from_v: str, to_v: str, rels: list[Release], lang: str,
              max_chars: int, status=lambda msg: None) -> Digest:
    d = Digest(by=f"{provider.name} ({provider.model})")
    lang_name = LANG_NAMES.get(lang, lang)
    system = _SYSTEM.format(software=software, from_v=from_v, to_v=to_v, lang=lang_name)
    chunks = _chunks(rels, max_chars)

    if len(chunks) == 1:
        # Small range: one call does extraction and summary.
        status(f"{provider.model}: обобщавам {len(rels)} версии...")
        try:
            out = provider.complete_json(system + "\n\n" + _REDUCE.format(lang=lang_name), chunks[0],
                                         _schema({**_ITEMS_PROPS, **_SUMMARY_PROPS}))
        except LLMError as e:
            d.errors.append(str(e))
            return d
        for k in CATEGORIES:
            d.items[k] = [i for i in out.get(k, []) if isinstance(i, dict)]
        d.summary, d.risk, d.recommendations = out.get("summary", ""), out.get("risk", ""), out.get("recommendations", [])
        _verify_quotes(d, rels)
        return d

    for i, chunk in enumerate(chunks, 1):
        status(f"{provider.model}: извличам промени, част {i}/{len(chunks)}...")
        try:
            out = provider.complete_json(system, chunk, _schema(_ITEMS_PROPS))
        except LLMError as e:
            d.errors.append(f"част {i}: {e}")
            continue
        for k in CATEGORIES:
            d.items[k] += [x for x in out.get(k, []) if isinstance(x, dict)]

    _verify_quotes(d, rels)
    status(f"{provider.model}: общо обобщение...")
    try:
        out = provider.complete_json(system + "\n\n" + _REDUCE.format(lang=lang_name),
                                     json.dumps(d.items, ensure_ascii=False), _schema(_SUMMARY_PROPS))
        d.summary, d.risk, d.recommendations = out.get("summary", ""), out.get("risk", ""), out.get("recommendations", [])
    except LLMError as e:
        d.errors.append(f"обобщение: {e}")
    return d
