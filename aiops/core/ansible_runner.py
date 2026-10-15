"""Thin wrapper around ansible-playbook from the project venv."""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PlaybookResult:
    returncode: int
    failed_hosts: dict[str, str]  # host -> "unreachable" | "failed"
    output: str


def _ansible_bin(name: str) -> str:
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.exists():
        return str(venv_bin)
    found = shutil.which(name)
    if not found:
        raise RuntimeError(f"{name} not found; install requirements.txt into the venv")
    return found


def single_host_inventory(targets: list[str]) -> Path:
    """Write a temporary inventory for `[user@]host[:port]` targets."""
    lines = []
    for t in targets:
        user, _, hostport = t.rpartition("@")
        host, port = hostport, None
        if hostport.count(":") == 1:
            host, port = hostport.split(":")
        vars_ = [f"ansible_host={host}"]
        if user:
            vars_.append(f"ansible_user={user}")
        if port:
            vars_.append(f"ansible_port={port}")
        lines.append(f"{host} {' '.join(vars_)}")
    fd, path = tempfile.mkstemp(prefix="aiops-inv-", suffix=".ini")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return Path(path)


_RECAP = re.compile(r"^(\S+)\s+:\s+ok=\d+\s+changed=\d+\s+unreachable=(\d+)\s+failed=(\d+)", re.M)


def run_playbook(
    playbook: Path,
    inventory: str,
    extra_vars: dict[str, str],
    become: bool = False,
    limit: str | None = None,
    echo=None,
) -> PlaybookResult:
    cmd = [_ansible_bin("ansible-playbook"), "-i", inventory, str(playbook)]
    for k, v in extra_vars.items():
        cmd += ["-e", f"{k}={v}"]
    if become:
        cmd.append("--become")
    if limit:
        cmd += ["--limit", limit]
    env = {**os.environ, "ANSIBLE_NOCOLOR": "1", "ANSIBLE_RETRY_FILES_ENABLED": "0"}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    out = []
    for line in proc.stdout:
        out.append(line)
        if echo:
            echo(line.rstrip())
    proc.wait()
    text = "".join(out)
    failed = {}
    for host, unreachable, failed_n in _RECAP.findall(text):
        if int(unreachable):
            failed[host] = "unreachable"
        elif int(failed_n):
            failed[host] = "failed"
    return PlaybookResult(proc.returncode, failed, text)
