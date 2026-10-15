"""Changelog sources and the software-name registry."""

from aiops.agents.changelog.model import Release
from aiops.core.webcache import WebCache

HOUR = 3600
DAY = 24 * HOUR


class Source:
    name = ""        # display name
    kind = ""        # github | comet | openstack
    dates_from_notes = False  # True when release dates are only known after fetching the notes

    def __init__(self, web: WebCache):
        self.web = web

    def releases(self) -> list[Release]:
        raise NotImplementedError

    def resolve(self, v: str, rels: list[Release]) -> str:
        """Map user input (e.g. an OpenStack series name) to a version string. Default: as given."""
        return v

    def fill_notes(self, rels: list[Release], status=lambda msg: None) -> None:
        """Populate Release.notes for the given releases (no-op when releases() already did)."""


# OpenStack projects people usually mean by bare name.
OPENSTACK_PROJECTS = {
    "nova", "neutron", "keystone", "glance", "cinder", "swift", "horizon", "heat", "octavia", "ironic",
    "designate", "barbican", "manila", "placement", "magnum", "trove", "aodh", "ceilometer", "gnocchi",
    "kolla", "kolla-ansible", "openstack-ansible", "skyline-apiserver", "skyline-console", "masakari",
}

ALIASES = {
    "jumpserver": "github:jumpserver/jumpserver",
    "comet": "comet",
    "cometbackup": "comet",
    "comet-backup": "comet",
}


def resolve_source(spec: str, web: WebCache) -> Source:
    from aiops.agents.changelog.sources.comet import CometSource
    from aiops.agents.changelog.sources.github import GitHubSource
    from aiops.agents.changelog.sources.openstack import OpenStackReleaseSource, OpenStackSource

    s = ALIASES.get(spec.lower(), spec)
    low = s.lower()
    if low == "comet":
        return CometSource(web)
    if low == "openstack":
        return OpenStackReleaseSource(web)
    for prefix in ("openstack:", "openstack/"):
        if low.startswith(prefix):
            return OpenStackSource(web, s[len(prefix):])
    if low in OPENSTACK_PROJECTS:
        return OpenStackSource(web, low)
    if low.startswith("github:"):
        return GitHubSource(web, s[len("github:"):])
    if s.count("/") == 1:
        return GitHubSource(web, s)
    raise ValueError(
        f"непознат софтуер '{spec}'. Използвай: jumpserver, comet, openstack (серии), nova/neutron/... (OpenStack проекти), "
        f"openstack:<проект>, github:<owner>/<repo>"
    )
