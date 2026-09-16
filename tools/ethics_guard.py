#!/usr/bin/env python3
"""CI ethics guard: fail if any live-network capability appears in wpacrack/.

The tool is strictly file-in / verdict-out. This enforces the proposal's
"Scope & Ethics" commitment: no sockets, no packet injection, no raw transmit.
"""

import pathlib
import re
import sys

BANNED = [
    r"\bimport\s+socket\b",
    r"\bfrom\s+socket\b",
    r"\bscapy\b",
    r"\bAF_PACKET\b",
    r"\bPF_PACKET\b",
    r"\bsendp\s*\(",
    r"\bsend\s*\(",
    r"\bsniff\s*\(",
]

root = pathlib.Path(__file__).resolve().parent.parent / "wpacrack"
pattern = re.compile("|".join(BANNED))
violations = []
for py in root.rglob("*.py"):
    for i, line in enumerate(py.read_text().splitlines(), 1):
        if pattern.search(line):
            violations.append(f"{py}:{i}: {line.strip()}")

if violations:
    print("ETHICS GUARD FAILED — live-network capability detected:")
    print("\n".join(violations))
    sys.exit(1)
print("ETHICS GUARD PASSED: wpacrack/ is file-in / verdict-out only.")
