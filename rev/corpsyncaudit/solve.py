#!/usr/bin/env python3
"""
CorpSyncAudit solver
--------------------
The audit GUI (CorpSyncAudit.exe) embeds a backdoor that reconstructs x64
shellcode from "replication" log lines whose Region= values are in a 32-entry
hash table of world regions (not the benign BRANCH_OFFICE_* labels).

Each matching line encodes 4 payload bytes in the timestamp fields, with the
5-bit region index selecting which fields are XORed with fixed mid values.
A day-of-week constant and a 4-byte session key (0xf07ec6a4) finish the decode.

Only logs/sync_20260412_192364.log carries the stager. The recovered command is:

  net user backup_admin <base64> /add &&
  net localgroup "Remote Desktop Users" backup_admin /add

The base64 password is the HTB flag.
"""

from __future__ import annotations

import base64
import re
import sys
from pathlib import Path

REGION_TABLE = [
    0x96409FF6AEB69064,
    0xA388696D5E9AE1F2,
    0xFF5CA9DFB7509BDB,
    0xB085F689913F3762,
    0x2F9C1DB0846DE64E,
    0xEFFC2B3669DB8292,
    0x1894463F0FBC0F9E,
    0x81E4AA341307782B,
    0xB8609753FEF8B18D,
    0xE0D8367AAF202156,
    0xF33F3E31C257DABD,
    0x9E7A78F42B97B4D6,
    0xC4427B2AEF260591,
    0x0E9EDCA9CBBA3552,
    0xCE31708176B158D1,
    0xEC3ECA83966F9F99,
    0xF12A05C282F1CAA2,
    0x4BAD433B483526EA,
    0xFC1219E953FEA0CB,
    0xEE0ABCF320013087,
    0x7A397F728FBF9028,
    0xC7152B1900FDEA7E,
    0xFCFA75D56995F8D9,
    0xF2A35E0E90372A96,
    0x3E9DF7003FF6F7F7,
    0xA3ACD9B547AC1C68,
    0xE5E1111FD25D5A88,
    0x426D3EBF9F854A23,
    0x29FB46F83399EBB4,
    0xAC1B5FD672FCB7EE,
    0xFE81E97108117D59,
    0x9FD85A088CFD699A,
]

DOW = {
    "Monday": 1,
    "Tuesday": 2,
    "Wednesday": 3,
    "Thursday": 4,
    "Friday": 5,
    "Saturday": 6,
    "Sunday": 7,
}

# Key observed after the environment-check block (also the API-hash salt used
# while resolving inject helpers). Under the intended "clean" conditions it is
# the constant 0xf07ec6a4.
SESSION_KEY = 0xF07EC6A4

LINE_RE = re.compile(
    r"^(\w+), (\d+)/(\d+)/(\d+) (\d+):(\d+):(\d+) (\w+) (\w+) \| Region=(\S+)"
)


def rol64(x: int, r: int) -> int:
    r &= 63
    return ((x >> r) | (x << (64 - r))) & 0xFFFFFFFFFFFFFFFF


def hash_region(name: str) -> int:
    """FNV-1a-ish mix + Murmur-style finalizer used by the binary."""
    h = 0xCBF29CE484222325
    for ch in name.encode():
        if 0x60 < ch < 0x7B:
            ch -= 0x20
        h = rol64((h ^ ch) * 0x100000001B3 & 0xFFFFFFFFFFFFFFFF, 0xD)
    u = (h ^ (h >> 0x21)) * 0xFF51AFD7ED558CCD & 0xFFFFFFFFFFFFFFFF
    u = (u ^ (u >> 0x21)) * 0xC4CEB9FE1A85EC53 & 0xFFFFFFFFFFFFFFFF
    return u ^ (u >> 0x21)


def encode_line(
    dayname: str,
    day: int,
    month: int,
    year: int,
    hour: int,
    minute: int,
    second: int,
    _ampm: str,
    tz: str,
    region_idx: int,
) -> bytes:
    # Region index bits (MSB..LSB) gate XOR of hour/min/sec/day/month.
    bits = "".join("1" if (region_idx >> (4 - i)) & 1 else "0" for i in range(5))

    h, m, s = hour, minute, second
    if tz == "GMT":
        mid = (m + h - s) // 2
        h, m, s = h - mid, mid, m - mid

    def maybe_xor(val: int, mid: int, bit: str) -> int:
        return val ^ mid if bit == "1" else val

    h = maybe_xor(h, 0x0C, bits[0])
    m = maybe_xor(m, 0x1E, bits[1])
    s = maybe_xor(s, 0x1E, bits[2])
    day_v = maybe_xor(day, 0x10, bits[3])
    mon_v = maybe_xor(month, 6, bits[4])
    year_v = (year - 0x7C6) & 0xFFFFFFFF  # year - 1990

    packed = (
        ((mon_v & 0xFFFFFFFF) << 6)
        | ((h & 0xFFFFFFFF) << 0x1B)
        | ((m & 0xFFFFFFFF) << 0x15)
        | ((s & 0xFFFFFFFF) << 0x0F)
        | ((day_v & 0xFFFFFFFF) << 10)
        | (year_v & 0xFFFFFFFF)
    ) & 0xFFFFFFFF

    dow = DOW.get(dayname, 1)
    return bytes(
        [
            ((packed >> 24) & 0xFF) ^ dow,
            ((packed >> 16) & 0xFF) ^ dow,
            ((packed >> 8) & 0xFF) ^ dow,
            (packed & 0xFF) ^ dow,
        ]
    )


def decode_log(path: Path) -> bytes:
    xored = bytearray()
    for line in path.read_text(errors="replace").splitlines():
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        dayname, dd, mm, yyyy, hh, mi, ss, ampm, tz, region = m.groups()
        digest = hash_region(region)
        if digest not in REGION_TABLE:
            continue
        idx = REGION_TABLE.index(digest)
        xored += encode_line(
            dayname,
            int(dd),
            int(mm),
            int(yyyy),
            int(hh),
            int(mi),
            int(ss),
            ampm,
            tz,
            idx,
        )

    key_bytes = [
        (SESSION_KEY >> 24) & 0xFF,
        (SESSION_KEY >> 16) & 0xFF,
        (SESSION_KEY >> 8) & 0xFF,
        SESSION_KEY & 0xFF,
    ]
    return bytes(b ^ key_bytes[i % 4] for i, b in enumerate(xored))


def extract_flag(shellcode: bytes) -> str:
    # cmd embedded in WinExec stager: net user backup_admin <b64> /add && ...
    m = re.search(rb"backup_admin\s+(\S+)\s+/add", shellcode)
    if not m:
        raise SystemExit("could not find password blob in shellcode")
    return base64.b64decode(m.group(1)).decode()


def main() -> None:
    root = Path(__file__).resolve().parent
    log = root / "logs" / "sync_20260412_192364.log"
    if len(sys.argv) > 1:
        log = Path(sys.argv[1])

    shellcode = decode_log(log)
    (root / "shellcode.bin").write_bytes(shellcode)
    flag = extract_flag(shellcode)
    (root / "flag.txt").write_text(flag + "\n")
    print(flag)
    # sanity: classic x64 Win exec prologue
    assert shellcode[:4] == bytes.fromhex("fc4883e4"), shellcode[:16].hex()


if __name__ == "__main__":
    main()
