"""Reversible masking of hostnames and IP addresses before text leaves the machine."""

import ipaddress
import re

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")


class Masker:
    """Replaces host names and non-loopback/non-wildcard IPs with stable placeholders.

    Loopback and wildcard addresses are kept: they carry the exposure semantics the model needs.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._fwd: dict[str, str] = {}
        self._rev: dict[str, str] = {}

    def add_hostnames(self, names):
        # Longest first so "web1.example.com" is replaced before "web1".
        for name in sorted({n for n in names if n}, key=len, reverse=True):
            self._token(name, "host")

    def _token(self, value: str, kind: str) -> str:
        if value not in self._fwd:
            token = f"<{kind}-{sum(1 for t in self._rev if t.startswith(f'<{kind}-')) + 1}>"
            self._fwd[value] = token
            self._rev[token] = value
        return self._fwd[value]

    def _mask_ip(self, m: re.Match) -> str:
        raw = m.group(0)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return raw
        if ip.is_loopback or ip.is_unspecified:
            return raw
        return self._token(raw, "ip")

    def mask(self, text: str) -> str:
        if not self.enabled:
            return text
        for value, token in self._fwd.items():
            if not token.startswith("<ip-"):
                text = re.sub(rf"(?<![\w.-]){re.escape(value)}(?![\w-])", token, text)
        text = _IPV4.sub(self._mask_ip, text)
        return _IPV6.sub(self._mask_ip, text)

    def unmask(self, text: str) -> str:
        for token, value in self._rev.items():
            text = text.replace(token, value)
        return text
