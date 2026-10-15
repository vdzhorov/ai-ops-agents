"""GitHub releases (with notes); falls back to tags when a project publishes no releases."""

import json
import os
import re

from aiops.agents.changelog.model import Release, is_prerelease, version_key
from aiops.agents.changelog.sources import HOUR, Source
from aiops.core.webcache import FetchError

API = "https://api.github.com"


def _line(version: str) -> str:
    nums = re.match(r"v?(\d+)(?:\.(\d+))?", version)
    if not nums:
        return ""
    return nums.group(1) + (f".{nums.group(2)}" if nums.group(2) else "")


class GitHubSource(Source):
    kind = "github"

    def __init__(self, web, repo: str):
        super().__init__(web)
        self.repo = repo.strip("/")
        self.name = f"github:{self.repo}"
        token = os.getenv("GITHUB_TOKEN")
        self.headers = {"Accept": "application/vnd.github+json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def _pages(self, path: str, max_pages: int = 20) -> list[dict]:
        items = []
        for page in range(1, max_pages + 1):
            url = f"{API}/repos/{self.repo}/{path}?per_page=100&page={page}"
            try:
                body = self.web.get(url, ttl=3 * HOUR, headers=self.headers)
            except FetchError as e:
                if "403" in str(e) or "429" in str(e):
                    raise FetchError(f"{e}\nGitHub rate limit (60 заявки/час без token) — сложи GITHUB_TOKEN в .env") from e
                raise
            batch = json.loads(body)
            items += batch
            if len(batch) < 100:
                break
        return items

    def releases(self) -> list[Release]:
        rels = []
        for r in self._pages("releases"):
            if r.get("draft"):
                continue
            v = r["tag_name"]
            rels.append(Release(
                version=v,
                line=_line(v),
                date=(r.get("published_at") or "")[:10],
                prerelease=bool(r.get("prerelease")) or is_prerelease(v),
                url=r.get("html_url", ""),
                notes=(r.get("body") or "").replace("\r\n", "\n").strip() or "(няма текст в release-а)",
            ))
        if rels:
            return rels
        # No GitHub releases: versions from tags, without notes.
        for t in self._pages("tags"):
            v = t["name"]
            if version_key(v)[0]:
                rels.append(Release(v, _line(v), prerelease=is_prerelease(v),
                                    url=f"https://github.com/{self.repo}/tree/{v}",
                                    notes="(проектът няма GitHub releases — само tag, без release notes)"))
        return rels
