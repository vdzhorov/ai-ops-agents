"""Offline tests for the changelog tool: python -m unittest discover tests"""

import unittest

from aiops.agents.changelog.htmltext import html_to_md
from aiops.agents.changelog.model import Release, find, latest, select_range, version_key


def rel(v, line="", rank=()):
    return Release(v, line=line, prerelease=version_key(v)[1] == 0, rank=rank)


class VersionOrderTest(unittest.TestCase):
    def test_ordering(self):
        vs = ["v5.0.0", "v4.10.19", "v5.0.0-rc1", "31.0.0.0rc1", "31.0.0", "1.2", "1.2.1", "31.3.1-2"]
        self.assertEqual(sorted(vs, key=version_key),
                         ["1.2", "1.2.1", "v4.10.19", "v5.0.0-rc1", "v5.0.0", "31.0.0.0rc1", "31.0.0", "31.3.1-2"])

    def test_equivalent_forms(self):
        self.assertEqual(version_key("v1.2"), version_key("1.2.0"))


class RangeTest(unittest.TestCase):
    def setUp(self):
        self.rels = [rel(v, v.lstrip("v").rsplit(".", 1)[0]) for v in
                     ["v3.10.22", "v3.10.23", "v4.10.15", "v4.10.16", "v4.10.19", "v5.0.0-rc1", "v5.0.0"]]

    def test_includes_intermediate_versions_of_other_lines(self):
        got = [r.version for r in select_range(self.rels, "v4.10.15", "v5.0.0")]
        self.assertEqual(got, ["v4.10.16", "v4.10.19", "v5.0.0"])  # not v3.10.x, not the rc

    def test_prereleases_opt_in(self):
        got = [r.version for r in select_range(self.rels, "4.10.19", "5.0.0", include_pre=True)]
        self.assertEqual(got, ["v5.0.0-rc1", "v5.0.0"])

    def test_reversed_arguments(self):
        self.assertEqual(select_range(self.rels, "v5.0.0", "v4.10.15"), select_range(self.rels, "v4.10.15", "v5.0.0"))

    def test_latest_per_line(self):
        newest, per_line = latest(self.rels)
        self.assertEqual(newest.version, "v5.0.0")
        self.assertEqual(per_line["3.10"].version, "v3.10.23")

    def test_series_rank_beats_old_year_numbers(self):
        # OpenStack: 2015.1.4 (kilo) is older than 31.0.0 (epoxy) despite the bigger number.
        rels = [rel("2015.1.4", "kilo", (1,)), rel("29.4.0", "caracal", (2,)), rel("30.0.0", "dalmatian", (3,)),
                rel("31.0.0", "epoxy", (4,))]
        self.assertEqual(latest(rels)[0].version, "31.0.0")
        self.assertEqual([r.version for r in select_range(rels, "29.4.0", "31.0.0")], ["30.0.0", "31.0.0"])
        self.assertIsNotNone(find(rels, "v31.0"))


class HtmlTest(unittest.TestCase):
    def test_lists_headings_and_noise(self):
        md = html_to_md('<h2>1.0<a class="headerlink" href="#x">¶</a></h2><ul><li><p>Fix <code>foo</code></p></li>'
                        '<li>Bar</li></ul><script>evil()</script>')
        self.assertEqual(md, "## 1.0\n\n- Fix `foo`\n- Bar")


if __name__ == "__main__":
    unittest.main()
