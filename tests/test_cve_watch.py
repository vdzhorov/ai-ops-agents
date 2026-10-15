"""Offline tests (no network, no LLM): python -m unittest discover tests"""

import unittest
from pathlib import Path

from aiops.agents.cve_watch.findings import Group, importance
from aiops.agents.cve_watch.hostfacts import _osv_kernel_name, detect_ecosystem, parse_collector_output
from aiops.agents.cve_watch.severity import severity_of
from aiops.core.masking import Masker

FIXTURE = Path(__file__).parent / "fixtures" / "facts" / "web-01.txt"


class HostFactsTest(unittest.TestCase):
    def setUp(self):
        self.hf = parse_collector_output("web-01", FIXTURE.read_text())
        self.by_name = {(c.name, c.version): c for c in self.hf.components}

    def test_os_and_ecosystem(self):
        self.assertEqual(self.hf.ecosystem, "Debian:12")
        self.assertTrue(self.hf.is_root)
        self.assertEqual(self.hf.errors, [])

    def test_source_grouping(self):
        self.assertEqual(self.by_name[("openssl", "3.0.11-1~deb12u2")].binaries, ["libssl3", "openssl"])

    def test_usage_via_shared_library(self):
        u = self.hf.usage(self.by_name[("openssl", "3.0.11-1~deb12u2")])
        self.assertEqual(u.level, "network-exposed")
        self.assertIn("nginx", u.procs)

    def test_usr_merge_owner_lookup(self):
        # libc.so.6 is mapped from /usr/lib but dpkg registered /lib
        self.assertEqual(self.hf.usage(self.by_name[("glibc", "2.36-9+deb12u3")]).level, "network-exposed")

    def test_loopback_listener(self):
        self.assertEqual(self.hf.usage(self.by_name[("redis", "5:7.0.11-1+deb12u1")]).level, "local-listener")

    def test_installed_only(self):
        self.assertEqual(self.hf.usage(self.by_name[("curl", "7.88.1-10+deb12u5")]).level, "installed")

    def test_kernels(self):
        self.assertEqual(self.hf.usage(self.by_name[("linux", "6.1.76-1")]).level, "kernel-running")
        self.assertEqual(self.hf.usage(self.by_name[("linux", "6.1.69-1")]).level, "kernel-inactive")


class ParserEdgeCasesTest(unittest.TestCase):
    def test_systemd_socket_activation_not_a_consumer(self):
        from aiops.agents.cve_watch.hostfacts import _parse_ss
        s = _parse_ss(['tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3),("systemd",pid=1,fd=50))'])
        self.assertEqual(s[0].procs, ["sshd"])
        s = _parse_ss(['tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("systemd",pid=1,fd=50))'])
        self.assertEqual(s[0].procs, ["systemd"])

    def test_ubuntu_signed_and_unsigned_kernel_merge(self):
        text = "\n".join([
            "@@@SECTION META", "uid=0", "kernel=6.8.0-84-generic",
            "@@@SECTION OS_RELEASE", 'ID=ubuntu', 'VERSION_ID="24.04"', 'VERSION="24.04.3 LTS (Noble Numbat)"',
            "@@@SECTION PKG_DPKG",
            "ii \tlinux-image-6.8.0-84-generic\tlinux-signed\t6.8.0-84.84\t6.8.0-84.84",
            "ii \tlinux-modules-6.8.0-84-generic\tlinux\t6.8.0-84.84\t6.8.0-84.84",
            "@@@SECTION END",
        ])
        hf = parse_collector_output("vm", text)
        kernels = [c for c in hf.components if c.name == "linux"]
        self.assertEqual(len(kernels), 1)
        self.assertTrue(kernels[0].kernel_running)
        self.assertEqual(hf.ecosystem, "Ubuntu:24.04:LTS")


class EcosystemTest(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(detect_ecosystem({"ID": "ubuntu", "VERSION_ID": "22.04", "VERSION": "22.04.4 LTS (Jammy)"})[0],
                         "Ubuntu:22.04:LTS")
        self.assertEqual(detect_ecosystem({"ID": "rocky", "VERSION_ID": "9.4"})[0], "Rocky Linux:9")
        eco, note = detect_ecosystem({"ID": "rhel", "VERSION_ID": "9.4", "ID_LIKE": "fedora"})
        self.assertEqual(eco, "AlmaLinux:9")
        self.assertTrue(note)

    def test_signed_kernel(self):
        self.assertEqual(_osv_kernel_name("Debian:12", "linux-signed-amd64", "6.1.76+1"), ("linux", "6.1.76-1"))
        self.assertEqual(_osv_kernel_name("Ubuntu:22.04:LTS", "linux-signed-hwe-6.5", "6.5.0-1"), ("linux-hwe-6.5", "6.5.0-1"))


class SeverityTest(unittest.TestCase):
    def test_vendor_rating_wins(self):
        s = severity_of({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                                      {"type": "Ubuntu", "score": "medium"}]}, None)
        self.assertEqual((s.level, s.cvss, s.attack_vector), ("medium", 9.8, "N"))

    def test_rhel_summary_prefix(self):
        self.assertEqual(severity_of({"summary": "Important: openssl security update"}, None).level, "high")

    def test_debian_unimportant(self):
        aff = {"ecosystem_specific": {"urgency": "unimportant"}}
        s = severity_of({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}, aff)
        self.assertEqual(s.level, "low")


class MaskerTest(unittest.TestCase):
    def test_roundtrip(self):
        m = Masker()
        m.add_hostnames(["db"])
        masked = m.mask("db at 10.20.30.40:22, dbus on 127.0.0.1 and 0.0.0.0, pkg 1:9.2p1")
        self.assertNotIn("10.20.30.40", masked)
        self.assertIn("dbus", masked)
        self.assertIn("127.0.0.1", masked)
        self.assertIn("0.0.0.0", masked)
        self.assertIn("1:9.2p1", masked)
        self.assertTrue(masked.startswith("<host-1>"))
        self.assertEqual(m.unmask(masked), "db at 10.20.30.40:22, dbus on 127.0.0.1 and 0.0.0.0, pkg 1:9.2p1")


if __name__ == "__main__":
    unittest.main()
