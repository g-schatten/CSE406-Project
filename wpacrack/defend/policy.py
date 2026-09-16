"""Strong-passphrase policy checklist."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

COMMON = {
    "password", "password123", "12345678", "qwerty12345", "letmein",
    "admin", "adminadmin", "hunter2", "iloveyou", "00000000",
}


@dataclass
class PolicyResult:
    passphrase_len: int
    findings: List[str]
    verdict: str  # STRONG / WEAK

    def report(self) -> str:
        lines = [f"passphrase policy: {self.verdict} (length {self.passphrase_len})"]
        for f in self.findings:
            lines.append(f"  - {f}")
        return "\n".join(lines)


def evaluate(passphrase: str) -> PolicyResult:
    findings: List[str] = []
    ok = True
    if len(passphrase) < 15:
        findings.append("shorter than 15 characters (recommend >= 15 for WPA2-PSK)")
        ok = False
    classes = sum([
        any(c.islower() for c in passphrase),
        any(c.isupper() for c in passphrase),
        any(c.isdigit() for c in passphrase),
        any(not c.isalnum() for c in passphrase),
    ])
    if classes < 3:
        findings.append("uses fewer than 3 character classes")
        ok = False
    if passphrase.lower() in COMMON:
        findings.append("appears in a common-password list")
        ok = False
    if not findings:
        findings.append("meets length and character-class guidance; keep it unique and unguessable")
    findings.append("prefer WPA3-SAE-only; disable WPA2 transition mode")
    findings.append("Dragonblood (2020): keep SAE implementations patched; avoid compatibility mode")
    return PolicyResult(len(passphrase), findings, "STRONG" if ok else "WEAK")
