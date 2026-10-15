"""Comet Backup: versions from the docs sitemap, notes from each release-notes page."""

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from aiops.agents.changelog.htmltext import html_to_md
from aiops.agents.changelog.model import Release
from aiops.agents.changelog.sources import DAY, HOUR, Source

BASE = "https://docs.cometbackup.com"
_SLUG = re.compile(r"release-notes/((?:\d+-)+)([a-z-]*?)-?released</loc>")
_DATE = re.compile(r"([A-Z][a-z]+ \d{1,2}, \d{4})")


class CometSource(Source):
    kind = "comet"
    name = "Comet Backup"
    dates_from_notes = True

    def releases(self) -> list[Release]:
        sitemap = self.web.get(f"{BASE}/sitemap.xml", ttl=6 * HOUR)
        rels = {}
        for nums, track in _SLUG.findall(sitemap):
            version = nums.strip("-").replace("-", ".")
            slug = f"{nums}{track + '-' if track else ''}released"
            rels[version] = Release(
                version=version,
                line=track or "-",
                prerelease=track == "beta",
                url=f"{BASE}/release-notes/{slug}",
            )
        return list(rels.values())

    def _fetch(self, r: Release):
        page = self.web.get(r.url, ttl=30 * DAY, allow_404=True)
        if page is None:
            r.notes = "(страницата липсва)"
            return
        m = re.search(r"<article.*?</article>", page, re.S)
        text = html_to_md(m.group(0) if m else page)
        d = _DATE.search(text[:300])
        if d:
            try:
                r.date = datetime.strptime(d.group(1), "%B %d, %Y").strftime("%Y-%m-%d")
            except ValueError:
                pass
        # Drop the page title line ("26.8.8 'Voyager' released October 8, 2026 · 3 min read").
        r.notes = re.sub(r"^#+ .*?min read\s*", "", text, count=1, flags=re.S).strip()

    def fill_notes(self, rels: list[Release], status=lambda msg: None) -> None:
        todo = [r for r in rels if r.notes is None]
        if todo:
            status(f"Comet: изтеглям release notes за {len(todo)} версии...")
            with ThreadPoolExecutor(8) as ex:
                list(ex.map(self._fetch, todo))
