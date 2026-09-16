"""Verdict object shared by all attacks and the CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Status values
FOUND = "FOUND"            # a candidate verified
EXHAUSTED = "EXHAUSTED"    # searched the whole space, nothing matched (no false positive)
NA = "N/A"                 # the required field/handshake is absent; nothing to attempt
ERROR = "ERROR"            # could not run (e.g. unsupported KDV, missing SSID)


@dataclass
class Verdict:
    attack: str
    status: str
    passphrase: Optional[str] = None
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    tried: int = 0
    elapsed: float = 0.0
    detail: str = ""

    @property
    def rate(self) -> float:
        return self.tried / self.elapsed if self.elapsed > 0 else 0.0

    def line(self) -> str:
        head = f"[{self.attack}] {self.status}"
        if self.status == FOUND:
            head += f"  passphrase={self.passphrase!r}"
        bits = []
        if self.ssid is not None:
            bits.append(f"ssid={self.ssid}")
        if self.tried:
            bits.append(f"tried={self.tried}")
        if self.elapsed:
            bits.append(f"time={self.elapsed:.2f}s")
        if self.tried and self.elapsed:
            bits.append(f"rate={self.rate:,.0f}/s")
        if self.detail:
            bits.append(self.detail)
        return head + ("  (" + ", ".join(bits) + ")" if bits else "")
