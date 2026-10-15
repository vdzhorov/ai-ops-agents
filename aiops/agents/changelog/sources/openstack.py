"""OpenStack: versions from openstack/releases deliverables, notes from the reno pages on docs.openstack.org."""

import re
from concurrent.futures import ThreadPoolExecutor

import yaml

from aiops.agents.changelog.htmltext import html_to_md
from aiops.agents.changelog.model import Release, is_prerelease, version_key
from aiops.agents.changelog.sources import DAY, Source

RELEASES_RAW = "https://raw.githubusercontent.com/openstack/releases/master"
DOCS = "https://docs.openstack.org/releasenotes"
_H2 = re.compile(r"<h2>([^<]+)<a class=\"headerlink\"")
_MARKER = re.compile(r"-(eol|eom|em|eoal|last)$", re.I)  # end-of-life tags, not releases


class OpenStackSource(Source):
    kind = "openstack"

    def __init__(self, web, project: str):
        super().__init__(web)
        self.project = project
        self.name = f"OpenStack {project}"
        self._series: list[dict] = []

    def _series_list(self) -> list[dict]:
        if not self._series:
            data = yaml.safe_load(self.web.get(f"{RELEASES_RAW}/data/series_status.yaml", ttl=DAY))
            self._series = [s for s in data if s.get("status") != "future"]
        return self._series

    def _deliverable(self, series: dict) -> list[str]:
        ttl = 30 * DAY if series.get("status") == "end of life" else DAY
        body = self.web.get(f"{RELEASES_RAW}/deliverables/{series['name']}/{self.project}.yaml",
                            ttl=ttl, allow_404=True)
        if not body:
            return []
        return [r["version"] for r in (yaml.safe_load(body) or {}).get("releases", []) if r.get("version")]

    def releases(self) -> list[Release]:
        series = self._series_list()
        with ThreadPoolExecutor(8) as ex:
            versions = list(ex.map(self._deliverable, series))
        rels = {}
        # series_status.yaml is newest first; old series used year-based numbers (2015.1), so order by series.
        for idx, (s, vs) in enumerate(zip(series, versions)):
            label = s["name"] + (f" ({s['release-id']})" if s.get("release-id") else "")
            for v in vs:
                if not _MARKER.search(v):
                    rels.setdefault(v, Release(v, line=label, prerelease=is_prerelease(v), rank=(len(series) - idx,)))
        if not rels:
            raise ValueError(f"OpenStack проект '{self.project}' не е намерен в openstack/releases")
        return list(rels.values())

    def resolve(self, v: str, rels: list[Release]) -> str:
        """A series name or id ("epoxy", "2025.1") means the newest release of that series."""
        low = v.lower()
        for s in self._series_list():
            if low in (s["name"], str(s.get("release-id", ""))):
                in_series = [r for r in rels if r.line.split(" ")[0] == s["name"] and not r.prerelease]
                if in_series:
                    return max(in_series, key=lambda r: r.key).version
        return v

    def _series_notes(self, series: dict) -> dict[str, str]:
        """{version: markdown} from one series page; post-release notes ("31.3.1-2") fold into their base."""
        ttl = 30 * DAY if series.get("status") == "end of life" else DAY
        page = None
        for slug in (series.get("release-id"), series["name"]):
            if slug:
                page = self.web.get(f"{DOCS}/{self.project}/{slug}.html", ttl=ttl, allow_404=True)
                if page:
                    break
        if not page:
            return {}
        end = min(i for i in (page.find("docs-sidebar-section"), page.find("<footer"), len(page)) if i >= 0)
        heads = [(m.start(), m.group(1).strip()) for m in _H2.finditer(page, 0, end)]
        out: dict[str, str] = {}
        for i, (pos, version) in enumerate(heads):
            chunk = page[pos : heads[i + 1][0] if i + 1 < len(heads) else end]
            text = html_to_md(chunk)
            text = re.sub(r"^## [^\n]*\n", "", text).strip()  # version heading is shown by the report
            base = re.sub(r"-\d+$", "", version)
            out[base] = (out[base] + "\n\n" + text) if base in out else text
        return out

    def fill_notes(self, rels: list[Release], status=lambda msg: None) -> None:
        todo = [r for r in rels if r.notes is None]
        if not todo:
            return
        by_series = {s["name"]: s for s in self._series_list()}
        needed = sorted({r.line.split(" ")[0] for r in todo})
        status(f"OpenStack: release notes за {self.project}, серии: {', '.join(needed)}...")
        with ThreadPoolExecutor(6) as ex:
            pages = dict(zip(needed, ex.map(lambda n: self._series_notes(by_series[n]), needed)))
        for r in todo:
            notes = pages.get(r.line.split(" ")[0], {})
            text = notes.get(r.version)
            if text is None:  # "31.0.0" vs "31.0.0.0" style differences
                text = next((t for v, t in notes.items() if version_key(v) == r.key), None)
            r.notes = text or "(няма release notes за тази версия)"
            r.url = f"{DOCS}/{self.project}/"


class OpenStackReleaseSource(OpenStackSource):
    """OpenStack as a whole: the coordinated series (2025.1 Epoxy, ...) with their cross-project highlights."""

    def __init__(self, web):
        super().__init__(web, project="")
        self.name = "OpenStack"

    def releases(self) -> list[Release]:
        series = self._series_list()
        rels = []
        for idx, s in enumerate(series):  # newest first in series_status.yaml
            rid = str(s.get("release-id") or "")
            rels.append(Release(
                version=rid or s["name"],
                line=f"{s['name']} · {s.get('status', '')}",
                date=str(s.get("initial-release") or ""),
                prerelease=s.get("status") == "development",
                url=f"https://releases.openstack.org/{s['name']}/highlights.html",
                rank=(len(series) - idx,),
            ))
        return rels

    def resolve(self, v: str, rels: list[Release]) -> str:
        low = v.lower()
        for s in self._series_list():
            if low in (s["name"], str(s.get("release-id", ""))):
                return str(s.get("release-id") or s["name"])
        return v

    def _highlights(self, r: Release):
        ttl = 30 * DAY if "end of life" in r.line else DAY
        page = self.web.get(r.url, ttl=ttl, allow_404=True)
        if not page:
            r.notes = "(няма публикувани highlights за тази серия)"
            return
        start = page.find("<h1")
        markers = ("docs-actions", "docs-byline", "<footer", "docs-sidebar")  # page chrome after the content
        end = min([i for i in (page.find(m, max(start, 0)) for m in markers) if i >= 0] + [len(page)])
        text = html_to_md(page[start if start >= 0 else 0 : end])
        r.notes = re.sub(r"^# [^\n]*\n", "", text).strip()

    def fill_notes(self, rels: list[Release], status=lambda msg: None) -> None:
        todo = [r for r in rels if r.notes is None]
        if todo:
            status(f"OpenStack: release highlights за {len(todo)} серии...")
            with ThreadPoolExecutor(6) as ex:
                list(ex.map(self._highlights, todo))
