"""OSV.dev client: exact version matching for distro packages, with an on-disk cache of vuln records."""

import gzip
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

API = "https://api.osv.dev/v1"
BATCH = 1000


_KEEP = ("id", "summary", "details", "modified", "published", "withdrawn", "severity", "upstream", "aliases", "related")


def slim(rec: dict) -> dict:
    """Drop what we never read: kernel records list every version of every release (megabytes each)."""
    out = {k: rec[k] for k in _KEEP if k in rec}
    if len(out.get("details", "")) > 3000:  # the prompt uses the first 1500 chars
        out["details"] = out["details"][:3000]
    out["affected"] = [
        {k: a[k] for k in ("package", "ranges", "ecosystem_specific") if k in a}
        for a in rec.get("affected", [])
    ]
    for a in out["affected"]:
        if "ecosystem_specific" in a:
            a["ecosystem_specific"] = {k: v for k, v in a["ecosystem_specific"].items() if k != "binaries"}
    return out


class OSVClient:
    def __init__(self, cache_dir: Path, ttl_days: float = 30):
        self.cache_dir = cache_dir / "osv"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # Records are re-fetched when OSV reports a newer `modified`; the TTL is only a safety net.
        self.ttl = ttl_days * 86400
        self.fetched = 0
        self._http = httpx.Client(timeout=120, headers={"User-Agent": "aiops-cve-watch"})

    def _post(self, path: str, body: dict) -> dict:
        for attempt in range(4):
            try:
                r = self._http.post(f"{API}{path}", json=body)
                if r.status_code < 500:
                    r.raise_for_status()
                    return r.json()
            except httpx.TransportError:
                pass
            time.sleep(2**attempt)
        raise RuntimeError(f"OSV {path} failed after retries")

    def match(self, queries: list[tuple[str, str, str]], status=lambda msg: None) -> list[dict[str, str]]:
        """queries: (ecosystem, name, version) -> {vuln id: modified} per query. Always fresh, never cached.

        Large result sets (kernels: thousands of IDs) are paged through querybatch, which returns
        1000 IDs per page in a few seconds (the single-query endpoint pages at 150)."""
        results: list[dict[str, str]] = [{} for _ in queries]
        pending = [(i, None) for i in range(len(queries))]  # (query index, page token)
        page = 0
        while pending:
            if page:
                names = ", ".join(sorted({queries[i][1] for i, _ in pending}))
                status(f"OSV: следваща страница за {names} ({sum(len(results[i]) for i, _ in pending)} до момента)")
            page += 1
            next_pending = []
            for start in range(0, len(pending), BATCH):
                chunk = pending[start : start + BATCH]
                body = {"queries": []}
                for i, token in chunk:
                    e, n, v = queries[i]
                    q = {"package": {"ecosystem": e, "name": n}, "version": v}
                    if token:
                        q["page_token"] = token
                    body["queries"].append(q)
                resp = self._post("/querybatch", body)
                for (i, _), res in zip(chunk, resp.get("results", [])):
                    results[i].update({v["id"]: v.get("modified", "") for v in res.get("vulns", [])})
                    if res.get("next_page_token"):
                        next_pending.append((i, res["next_page_token"]))
            pending = next_pending
        return results

    def _cache_path(self, vuln_id: str) -> Path:
        return self.cache_dir / (vuln_id.replace("/", "_").replace(":", "_") + ".json.gz")

    def _cached(self, vuln_id: str, modified: str) -> dict | None:
        p = self._cache_path(vuln_id)
        if not p.exists() or time.time() - p.stat().st_mtime > self.ttl:
            return None
        try:
            rec = json.loads(gzip.decompress(p.read_bytes()))
        except (OSError, EOFError, json.JSONDecodeError):
            return None
        # querybatch and the record differ in sub-second precision; compare to the second.
        if modified and rec.get("modified", "")[:19] < modified[:19]:
            return None
        return rec

    def get(self, vuln_id: str, modified: str = "") -> dict:
        rec = self._cached(vuln_id, modified)
        if rec is not None:
            return rec
        p = self._cache_path(vuln_id)
        for attempt in range(4):
            try:
                r = self._http.get(f"{API}/vulns/{vuln_id}")
                if r.status_code == 404:
                    return {}
                if r.status_code < 500:
                    r.raise_for_status()
                    rec = slim(r.json())
                    p.write_bytes(gzip.compress(json.dumps(rec).encode(), compresslevel=6))
                    self.fetched += 1
                    return rec
            except httpx.TransportError:
                pass
            time.sleep(2**attempt)
        raise RuntimeError(f"OSV vuln {vuln_id} fetch failed")

    def get_many(self, ids: dict[str, str], workers: int = 32, on_progress=None) -> dict[str, dict]:
        """ids: {vuln id: modified}. Only new or changed records hit the network."""
        uniq = sorted(ids)
        out = {}
        with ThreadPoolExecutor(workers) as ex:
            for i, (vid, rec) in enumerate(zip(uniq, ex.map(lambda v: self.get(v, ids[v]), uniq)), 1):
                out[vid] = rec
                if on_progress and (i % 50 == 0 or i == len(uniq)):
                    on_progress(i, len(uniq))
        return out
