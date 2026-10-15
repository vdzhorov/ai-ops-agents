"""Releases, version ordering and range selection shared by all changelog sources."""

import re
from dataclasses import dataclass

_PRE_RANK = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "pre": 3, "rc": 3}
_PRE = re.compile(r"^(dev|alpha|a|beta|b|pre|rc)\.?(\d*)")


def normalize(v: str) -> str:
    return v.strip().lstrip("vV")


def version_key(v: str) -> tuple:
    """Sortable key: 1.2 == 1.2.0, 1.2.0rc1 < 1.2.0 < 1.2.0-2 (post release / packaging suffix)."""
    s = normalize(v)
    m = re.match(r"(\d+(?:\.\d+)*)(.*)", s)
    if not m:
        return ((), 9, 0, s)
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums += (0,) * max(0, 4 - len(nums))
    rest = m.group(2).lower().lstrip(".-_+~")
    pre = _PRE.match(rest)
    if pre:
        return (nums, 0, _PRE_RANK[pre.group(1)], int(pre.group(2) or 0))
    if not rest:
        return (nums, 1, 0, 0)
    post = re.match(r"(\d+)", rest)
    return (nums, 2, int(post.group(1)) if post else 0, 0)


def is_prerelease(v: str) -> bool:
    return version_key(v)[1] == 0


@dataclass
class Release:
    version: str                 # as published, e.g. "v4.10.19", "31.3.1", "26.8.8"
    line: str = ""               # release line / track / series, e.g. "4.10", "voyager", "epoxy (2025.1)"
    date: str = ""               # YYYY-MM-DD when known
    prerelease: bool = False
    url: str = ""
    notes: str | None = None     # markdown; filled lazily by the source
    rank: tuple = ()             # sorts before the version number (OpenStack: series order)

    @property
    def key(self):
        return (self.rank, version_key(self.version))


def sort_releases(rels: list[Release]) -> list[Release]:
    return sorted(rels, key=lambda r: r.key)


def find(rels: list[Release], v: str) -> Release | None:
    want = normalize(v)
    for r in rels:
        if normalize(r.version) == want:
            return r
    k = version_key(v)  # "1.2" matches "1.2.0"
    return next((r for r in rels if version_key(r.version) == k), None)


def select_range(rels: list[Release], from_v: str, to_v: str, include_pre: bool = False) -> list[Release]:
    """Every release with from < version <= to, oldest first — including releases of other lines that fall
    between them by version number (e.g. 4.10.16..4.10.19 between 4.10.15 and 5.0.0)."""
    a, b = find(rels, from_v), find(rels, to_v)
    if a and b:
        lo, hi, key = a.key, b.key, (lambda r: r.key)
    else:  # unpublished version given: compare by version number only
        lo, hi, key = version_key(from_v), version_key(to_v), (lambda r: version_key(r.version))
    if lo > hi:
        lo, hi = hi, lo
    out = [r for r in rels if lo < key(r) <= hi and (include_pre or not r.prerelease)]
    return sort_releases(out)


def latest(rels: list[Release], include_pre: bool = False) -> tuple[Release | None, dict[str, Release]]:
    """Newest release overall and newest per line."""
    pool = [r for r in rels if include_pre or not r.prerelease]
    per_line: dict[str, Release] = {}
    for r in sort_releases(pool):
        per_line[r.line] = r
    newest = max(pool, key=lambda r: r.key) if pool else None
    return newest, per_line
