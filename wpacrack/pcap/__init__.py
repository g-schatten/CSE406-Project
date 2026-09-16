"""Minimal pcap / pcapng file reader.

Yields (linktype, packet_bytes) records. File-in only; never touches a socket.

Supported:
  - classic pcap (magic a1b2c3d4 / d4c3b2a1, both endiannesses)
  - pcapng (Section Header Block + Interface Description + Enhanced/Simple
    Packet Blocks)

Link types of interest:
  105 = IEEE 802.11 (no radio header)
  127 = IEEE 802.11 + radiotap
  119 = Prism (handled best-effort by the parser's radio-strip)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, List, Tuple

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D  # nanosecond-resolution classic pcap
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_MAGIC = 0x0A0D0D0A


@dataclass
class Packet:
    linktype: int
    data: bytes


def read_packets(path: str) -> List[Packet]:
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 4:
        raise ValueError("file too short to be a capture")
    first = struct.unpack(">I", blob[:4])[0]
    if first == PCAPNG_MAGIC:
        return list(_read_pcapng(blob))
    return list(_read_classic(blob))


def _read_classic(blob: bytes) -> Iterator[Packet]:
    magic = struct.unpack("<I", blob[:4])[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        endian = ">"
    else:
        raise ValueError(f"unrecognized pcap magic {magic:#010x}")
    # Global header is 24 bytes; network/linktype is the last 4 bytes.
    linktype = struct.unpack(endian + "I", blob[20:24])[0]
    off = 24
    n = len(blob)
    while off + 16 <= n:
        _ts_s, _ts_u, caplen, _origlen = struct.unpack(endian + "IIII", blob[off : off + 16])
        off += 16
        if off + caplen > n:
            break  # truncated final record
        yield Packet(linktype, blob[off : off + caplen])
        off += caplen


def _read_pcapng(blob: bytes) -> Iterator[Packet]:
    off = 0
    n = len(blob)
    endian = "<"
    linktypes: list[int] = []
    while off + 8 <= n:
        block_type = struct.unpack(endian + "I", blob[off : off + 4])[0]
        # Section Header Block: (re)establish endianness from its byte-order magic.
        if block_type == PCAPNG_MAGIC:
            bom = struct.unpack("<I", blob[off + 8 : off + 12])[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            block_type = struct.unpack(endian + "I", blob[off : off + 4])[0]
        block_len = struct.unpack(endian + "I", blob[off + 4 : off + 8])[0]
        if block_len < 12 or off + block_len > n:
            break
        body = blob[off + 8 : off + block_len - 4]
        if block_type == 0x00000001:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            linktypes.append(linktype)
        elif block_type == 0x00000006:  # Enhanced Packet Block
            iface = struct.unpack(endian + "I", body[0:4])[0]
            caplen = struct.unpack(endian + "I", body[8:12])[0]
            data = body[20 : 20 + caplen]
            lt = linktypes[iface] if iface < len(linktypes) else (linktypes[0] if linktypes else 127)
            yield Packet(lt, data)
        elif block_type == 0x00000003:  # Simple Packet Block
            caplen = struct.unpack(endian + "I", body[0:4])[0]
            data = body[4 : 4 + caplen]
            lt = linktypes[0] if linktypes else 127
            yield Packet(lt, data)
        off += block_len
