"""Remembered assessments, so repeated runs only send new or changed findings to a model."""

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from aiops.agents.cve_watch.findings import Assessment, Group, Vuln


class AssessmentCache:
    def __init__(self, path: Path, mode_label: str, lang: str):
        self.path = path
        self.prefix = f"{mode_label}|{lang}"
        try:
            self._data: dict[str, dict] = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            self._data = {}

    def key(self, g: Group, v: Vuln) -> str:
        """Changes whenever anything the verdict depends on changes: package, host context, fix, severity."""
        raw = json.dumps([self.prefix, g.component.key, g.context, v.id, v.fixed, v.severity.level], sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, g: Group, v: Vuln) -> Assessment | None:
        d = self._data.get(self.key(g, v))
        return Assessment(**d, cached=True) if d else None

    def put(self, g: Group, v: Vuln, a: Assessment):
        # Only real verdicts; errors and budget skips must be retried next time.
        if a.verdict == "unassessed" or "budget" in a.by:
            return
        d = asdict(a)
        d.pop("cached")
        self._data[self.key(g, v)] = d

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, ensure_ascii=False))
