"""Parse collector output into per-host facts and derive how each package is actually used."""

import re
from collections import defaultdict
from dataclasses import dataclass, field

# Usage levels, most relevant first.
USAGE_ORDER = [
    "network-exposed",   # loaded by a process listening on a non-loopback address
    "kernel-running",    # the kernel package that is currently booted
    "local-listener",    # loaded by a process listening on loopback only
    "running",           # loaded by some running process
    "installed",         # on disk, not loaded by anything we saw
    "kernel-inactive",   # installed kernel that is not the booted one
    "unknown",           # no runtime data (manual package list)
]

RPM_KERNEL_NAMES = {"kernel", "kernel-core", "kernel-modules", "kernel-modules-core", "kernel-modules-extra", "kernel-uek", "kernel-rt-core"}


@dataclass
class Socket:
    proto: str
    addr: str
    port: str
    procs: list[str]

    @property
    def loopback(self) -> bool:
        a = self.addr.strip("[]").split("%")[0]
        return a.startswith("127.") or a == "::1"

    def __str__(self):
        return f"{self.proto} {self.addr}:{self.port} ({','.join(self.procs) or '?'})"


@dataclass
class Component:
    """One OSV query unit: a Debian/Ubuntu source package or an RPM package at one version."""

    ecosystem: str
    name: str
    version: str
    binaries: list[str]
    is_kernel: bool = False
    kernel_running: bool = False

    @property
    def key(self):
        return (self.ecosystem, self.name, self.version)


@dataclass
class ComponentUsage:
    level: str
    procs: list[str] = field(default_factory=list)
    sockets: list[str] = field(default_factory=list)


@dataclass
class HostFacts:
    host: str
    os_id: str = ""
    os_version_id: str = ""
    os_pretty: str = ""
    ecosystem: str = ""
    ecosystem_note: str = ""
    kernel: str = ""
    arch: str = ""
    is_root: bool = False
    has_runtime: bool = True
    components: list[Component] = field(default_factory=list)
    sockets: list[Socket] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    # derived: binary package -> set of process names that map one of its files
    pkg_procs: dict[str, set[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def usage(self, comp: Component) -> ComponentUsage:
        if comp.is_kernel:
            return ComponentUsage("kernel-running" if comp.kernel_running else "kernel-inactive")
        if not self.has_runtime:
            return ComponentUsage("unknown")
        procs = sorted({p for b in comp.binaries for p in self.pkg_procs.get(b, ())})
        if not procs:
            return ComponentUsage("installed")
        socks = [s for s in self.sockets if set(s.procs) & set(procs)]
        exposed = [str(s) for s in socks if not s.loopback]
        local = [str(s) for s in socks if s.loopback]
        if exposed:
            return ComponentUsage("network-exposed", procs, exposed + local)
        if local:
            return ComponentUsage("local-listener", procs, local)
        return ComponentUsage("running", procs)


def _sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    cur = None
    for line in text.replace("\r", "").splitlines():
        if line.startswith("@@@SECTION "):
            cur = line.split(None, 1)[1].strip()
            out[cur]  # create even if empty
        elif cur:
            out[cur].append(line)
    return out


def detect_ecosystem(osr: dict[str, str]) -> tuple[str, str]:
    os_id = osr.get("ID", "").lower()
    like = osr.get("ID_LIKE", "").lower().split()
    ver = osr.get("VERSION_ID", "")
    major = ver.split(".")[0]
    if os_id == "debian":
        return (f"Debian:{major}" if major else "", "" if major else "Debian testing/sid is not supported by OSV")
    if os_id == "ubuntu":
        lts = ":LTS" if "LTS" in osr.get("VERSION", "") else ""
        return f"Ubuntu:{ver}{lts}", ""
    if os_id == "rocky":
        return f"Rocky Linux:{major}", ""
    if os_id == "almalinux":
        return f"AlmaLinux:{major}", ""
    if os_id in ("rhel", "centos", "ol") or "rhel" in like:
        return f"AlmaLinux:{major}", f"{os_id} {ver} is matched against AlmaLinux:{major} advisories (binary compatible)"
    if "debian" in like or "ubuntu" in like:
        return "", f"{os_id} is a Debian derivative without its own OSV feed"
    return "", f"unsupported OS '{os_id}'"


def _parse_ss(lines: list[str]) -> list[Socket]:
    socks = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5 or parts[0] in ("Netid", "Proto", "Active"):
            continue
        if parts[0].startswith(("tcp", "udp")) and len(parts) >= 6 and "/" in parts[-1] and not parts[-1].startswith("users"):
            local, procs = parts[3], [parts[-1].split("/", 1)[1]]  # netstat
        else:
            local = parts[4]
            procs = re.findall(r'\("([^"]+)",pid=', line)
        addr, _, port = local.rpartition(":")
        procs = set(procs)
        # Socket activation: systemd holds the socket but the real consumer is the service next to it.
        if len(procs) > 1:
            procs.discard("systemd")
        socks.append(Socket(parts[0], addr or "*", port, sorted(procs)))
    return socks


def _osv_kernel_name(ecosystem: str, name: str, version: str) -> tuple[str, str]:
    """Signed kernel sources carry no advisories; OSV tracks the unsigned source they are built from."""
    if not name.startswith("linux-signed"):
        return name, version
    if ecosystem.startswith("Debian"):
        # linux-signed-amd64 6.1.76+1  ->  linux 6.1.76-1
        head, sep, tail = version.rpartition("+")
        return "linux", f"{head}-{tail}" if sep else version
    return "linux" + name[len("linux-signed"):], version  # Ubuntu: linux-signed-hwe-6.5 -> linux-hwe-6.5


def _twin(path: str) -> str:
    return path[4:] if path.startswith("/usr/") else "/usr" + path


def parse_collector_output(host: str, text: str) -> HostFacts:
    s = _sections(text)
    hf = HostFacts(host=host)
    if "END" not in s:
        hf.errors.append("collector output is incomplete")

    meta = dict(l.split("=", 1) for l in s.get("META", []) if "=" in l)
    hf.kernel, hf.arch, hf.is_root = meta.get("kernel", ""), meta.get("arch", ""), meta.get("uid") == "0"

    osr = {}
    for l in s.get("OS_RELEASE", []):
        if "=" in l:
            k, v = l.split("=", 1)
            osr[k] = v.strip().strip('"')
    hf.os_id, hf.os_version_id, hf.os_pretty = osr.get("ID", ""), osr.get("VERSION_ID", ""), osr.get("PRETTY_NAME", "")
    hf.ecosystem, hf.ecosystem_note = detect_ecosystem(osr)

    groups: dict[tuple, list[str]] = defaultdict(list)
    kernel_flags: dict[tuple, tuple[bool, bool]] = {}
    for l in s.get("PKG_DPKG", []):
        f = l.split("\t")
        if len(f) < 5:
            continue
        binary = f[1].split(":")[0]
        src, src_ver = f[2] or binary, f[4] or f[3]
        key = (src, src_ver)
        groups[key].append(binary)
        if binary.startswith(("linux-image-", "linux-modules-")):
            running = binary in (f"linux-image-{hf.kernel}", f"linux-image-unsigned-{hf.kernel}", f"linux-modules-{hf.kernel}")
            was = kernel_flags.get(key, (False, False))
            kernel_flags[key] = (True, was[1] or running)
    for l in s.get("PKG_RPM", []):
        f = l.split("\t")
        if len(f) < 6:
            continue
        name, epoch, ver, rel, arch = f[:5]
        evr = f"{ver}-{rel}" if epoch in ("0", "", "(none)") else f"{epoch}:{ver}-{rel}"
        key = (name, evr)
        if name not in groups[key]:
            groups[key].append(name)
        if name in RPM_KERNEL_NAMES:
            kernel_flags[key] = (True, f"{ver}-{rel}.{arch}" == hf.kernel)
    merged: dict[tuple, Component] = {}
    for (name, ver), bins in groups.items():
        is_k, running = kernel_flags.get((name, ver), (False, False))
        name, ver = _osv_kernel_name(hf.ecosystem, name, ver)
        # linux and linux-signed collapse into one OSV package: merge instead of assessing twice.
        if (name, ver) in merged:
            m = merged[(name, ver)]
            m.binaries = sorted(set(m.binaries) | set(bins))
            m.is_kernel, m.kernel_running = m.is_kernel or is_k, m.kernel_running or running
        else:
            merged[(name, ver)] = Component(hf.ecosystem, name, ver, sorted(set(bins)), is_k, running)
    hf.components = list(merged.values())

    hf.sockets = _parse_ss(s.get("LISTEN", []))
    hf.modules = [m for m in s.get("MODULES", []) if m]
    hf.services = [x for x in s.get("SERVICES", []) if x]

    # file -> owning binary package. dpkg: "pkg[:arch][, pkg2]: /path"; rpm collector prints the same shape.
    owner: dict[str, str] = {}
    for l in s.get("FILE_OWNERS", []):
        if l.startswith("diversion by") or ": " not in l:
            continue
        pkgs, path = l.split(": ", 1)
        owner[path.strip()] = pkgs.split(",")[0].strip().split(":")[0]
    proc_files = [l.split("\t", 1) for l in s.get("PROC_FILES", []) if "\t" in l]
    hf.has_runtime = bool(proc_files)
    pkg_procs: dict[str, set[str]] = defaultdict(set)
    for comm, path in proc_files:
        pkg = owner.get(path) or owner.get(_twin(path))
        if pkg:
            pkg_procs[pkg].add(comm)
    hf.pkg_procs = dict(pkg_procs)
    if not hf.is_root:
        hf.errors.append("collector did not run as root: process/socket data is partial (use --become)")
    return hf


def parse_package_list(host: str, text: str, ecosystem: str) -> HostFacts:
    """Manual input: one `name version` per line (Debian/Ubuntu: source package names)."""
    hf = HostFacts(host=host, ecosystem=ecosystem, has_runtime=False, is_root=True)
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.replace("=", " ").split()
        if len(parts) >= 2:
            hf.components.append(Component(ecosystem, parts[0], parts[1], [parts[0]]))
    return hf
