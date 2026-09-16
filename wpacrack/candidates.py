"""Candidate passphrase generators: wordlist and hashcat-style mask."""

from __future__ import annotations

import itertools
import time
from typing import Iterator, Optional

MASK_CHARSETS = {
    "d": "0123456789",
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "a": None,  # filled below = l+u+d+s
}
MASK_CHARSETS["a"] = MASK_CHARSETS["l"] + MASK_CHARSETS["u"] + MASK_CHARSETS["d"] + MASK_CHARSETS["s"]


def iter_wordlist(path: str) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n").rstrip("\r")
            if pw:
                yield pw


def parse_mask(mask: str):
    """Turn a mask like '?d?d?l' into a list of charset strings."""
    sets = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i + 1]
            if token in MASK_CHARSETS:
                sets.append(MASK_CHARSETS[token])
            elif token == "?":
                sets.append("?")
            else:
                raise ValueError(f"unknown mask token ?{token}")
            i += 2
        else:
            sets.append(mask[i])  # literal character
            i += 1
    return sets


def mask_keyspace(mask: str) -> int:
    total = 1
    for s in parse_mask(mask):
        total *= len(s)
    return total


def iter_mask(mask: str, timebox: Optional[float] = None) -> Iterator[str]:
    """Yield candidates from a mask, optionally stopping after `timebox` seconds."""
    sets = parse_mask(mask)
    start = time.time()
    for combo in itertools.product(*sets):
        if timebox is not None and (time.time() - start) > timebox:
            return
        yield "".join(combo)
