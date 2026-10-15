"""Cached HTTP GET for tools that read public web data (gzip on disk, per-call TTL, stale fallback)."""

import gzip
import hashlib
import json
import time
from pathlib import Path

import httpx


class FetchError(Exception):
    pass


class WebCache:
    def __init__(self, cache_dir: Path, user_agent: str = "aiops"):
        self.dir = cache_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self._http = httpx.Client(timeout=60, follow_redirects=True, headers={"User-Agent": user_agent})

    def _path(self, url: str) -> Path:
        return self.dir / (hashlib.sha256(url.encode()).hexdigest()[:40] + ".gz")

    def get(self, url: str, ttl: float, headers: dict | None = None, allow_404: bool = False) -> str | None:
        """Body as text. ttl in seconds. A cached 404 is remembered (returns None) when allow_404."""
        p = self._path(url)
        cached = None
        if p.exists():
            cached = json.loads(gzip.decompress(p.read_bytes()))
            if time.time() - p.stat().st_mtime < ttl:
                return cached["body"]
        try:
            r = self._http.get(url, headers=headers or {})
        except httpx.HTTPError as e:
            if cached:
                return cached["body"]  # stale beats nothing when offline
            raise FetchError(f"{url}: {e.__class__.__name__}") from e
        if r.status_code == 404 and allow_404:
            body = None
        elif r.status_code >= 400:
            if cached:
                return cached["body"]
            raise FetchError(f"{url}: HTTP {r.status_code} {r.text[:200]}")
        else:
            body = r.text
        p.write_bytes(gzip.compress(json.dumps({"url": url, "body": body}).encode(), 6))
        return body

    def get_json(self, url: str, ttl: float, headers: dict | None = None):
        body = self.get(url, ttl, headers)
        return json.loads(body) if body is not None else None
