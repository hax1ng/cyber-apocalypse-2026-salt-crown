# Harvesting Severed Threads

## Challenge summary

We are given three artifacts:

```text
capture.pcapng   37 KB
dev_disk.img     1 GB
memory.elf       3.1 GB
```

The story says that the drive is encrypted, the memory is volatile, and some
unfinished malicious work was sent over the network. In plain English, the
challenge wants us to:

1. Pull encryption keys out of RAM.
2. Use them to open the drive.
3. Recover secrets from an encrypted database and the Linux keyring.
4. Decrypt the captured network traffic.
5. Join three flag fragments.

The final flag is:

```text
HTB{v0l4t1l3_1uk52_d3crypt10n_w1th_k3rn3l_k3yr1ng_4nd_w1r3gu4rd_3xf1l_brrr_brrr_brrr!!}
```

---

## 1. Initial triage

I started with the usual basic checks:

```bash
ls -lh
file capture.pcapng dev_disk.img memory.elf
```

`memory.elf` is a QEMU ELF physical-memory dump. `dev_disk.img` does not begin
with a normal LUKS header. Its first 4 MiB are zero, followed by encrypted-looking
data. This fits the shell command that can be found in memory:

```text
sudo cryptsetup open \
  --key-file /run/media/dev5812/dev_usb/luks_keyfile \
  --header /run/media/dev5812/dev_usb/dev_header.img \
  ./dev_disk.img dev_volume
```

The LUKS header and key file were stored separately on a USB device, so neither
is present in the supplied disk image. That sounds bad, but the drive was open
when RAM was captured. Linux therefore had the real volume key in memory.

Other useful commands left in RAM showed that the opened volume was mounted and
that an executable named `exfil` was run:

```text
sudo mount /dev/mapper/dev_volume dev_mnt/
sudo ./dev_mnt/pyz/exfil
```

Its output was also recoverable:

```text
[*] reading file into mutable buffer ...
[*] purging page cache ...
[*] creating wireguard interface ...
[*] encrypting & wiping plaintext from memory ...
[*] purging page cache again ...
sent 27525 encrypted bytes to ('10.0.0.1', 9999)
[+] done
```

That gives us a nice road map: the drive contains the tools, and the PCAP
contains a 27,525-byte encrypted payload sent through WireGuard.

---

## 2. Translating addresses in the memory dump

Before pulling kernel objects from RAM, I needed a way to translate between:

- an offset inside `memory.elf`,
- a physical address, and
- a Linux direct-map virtual address.

The main ELF `LOAD` segment maps file offset `0x1b3fe4` to physical address
`0x200000`. Therefore:

```text
physical address = memory.elf offset + 0x4c01c
```

For the kernel objects used in this challenge, the direct-map base was:

```text
ffff8a7280000000
```

So a direct-map pointer can be converted back to an ELF offset with:

```text
physical = virtual - 0xffff8a7280000000
file offset = physical - 0x4c01c
```

This small formula is what made the rest of the manual memory parsing possible.

---

## 3. Recovering the encrypted-drive key

### Finding the live dm-crypt configuration

The mapped volume had this UUID:

```text
fee4d343-9d49-470d-8315-00fb0e3101a0
```

Searching RAM for it led to the live dm-crypt key description:

```text
logon:cryptsetup:fee4d343-9d49-470d-8315-00fb0e3101a0-d0
```

Following references to that string found the active `crypt_config`. Important
fields from the structure were:

```text
cipher       = serpent-xts-plain64
start        = 0x2000 sectors
iv size      = 16 bytes
sector size  = 2048 bytes
sector shift = 2
key size     = 64 bytes
```

`0x2000` traditional 512-byte sectors is exactly 4 MiB, explaining the zero
area at the front of `dev_disk.img`.

The `crypt_config` itself did not contain the key because cryptsetup had loaded
it through the kernel keyring. Linux deliberately wipes the temporary copy
after installing a keyring-backed dm-crypt key.

### Following the keyring object

The key description led to a kernel `struct key`. Its payload pointed to a
`user_key_payload` containing 64 bytes of key material:

```text
6d092b4dcb45c0141e5306b7e8ee39ce
ecb8cb4b4b75f6f4e1b1f8f2d74773a0
d4ce7acf39d2197edc70fb453728b171
3ed52e396c50217e99299a6797d350df
```

Combined:

```text
6d092b4dcb45c0141e5306b7e8ee39ceecb8cb4b4b75f6f4e1b1f8f2d74773a0d4ce7acf39d2197edc70fb453728b1713ed52e396c50217e99299a6797d350df
```

### The slightly annoying IV detail

The cipher uses 2,048-byte crypto units, but `plain64` was still using
traditional 512-byte sector numbers because the optional
`iv_large_sectors` flag was not set.

That means:

```text
crypto unit 0 -> IV sector 0
crypto unit 1 -> IV sector 4
crypto unit 2 -> IV sector 8
...
```

Using IV values `0, 1, 2...` produces garbage after the first unit. This was an
easy place to get stuck because the ext4 superblock is inside the first unit
and initially appears to decrypt correctly.

I used Linux's unprivileged `AF_ALG` crypto interface for
`xts(serpent)` and decrypted sectors on demand. A reduced example is:

```python
import socket
import struct

SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_OP_DECRYPT = 0

key = bytes.fromhex(
    "6d092b4dcb45c0141e5306b7e8ee39ce"
    "ecb8cb4b4b75f6f4e1b1f8f2d74773a0"
    "d4ce7acf39d2197edc70fb453728b171"
    "3ed52e396c50217e99299a6797d350df"
)

alg = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
alg.bind(("skcipher", "xts(serpent)"))
alg.setsockopt(SOL_ALG, ALG_SET_KEY, key)
op, _ = alg.accept()

def decrypt_unit(ciphertext, unit_number):
    # 2048 / 512 = 4 traditional sectors per crypto unit
    iv_number = unit_number * 4
    iv = struct.pack("<Q", iv_number) + b"\0" * 8
    controls = [
        (SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
        (SOL_ALG, ALG_SET_IV, struct.pack("I", 16) + iv),
    ]
    op.sendmsg([ciphertext], controls)
    return op.recv(len(ciphertext))
```

The encrypted data begins at:

```text
8192 * 512 = 4194304 bytes
```

After fixing the IV numbering, the ext4 magic `53 ef` appeared where expected.

---

## 4. Looking through the decrypted drive

Rather than decrypting a whole 1 GB image, I wrote a small read-on-demand ext4
parser. It decrypted only the sectors needed for the superblock, group
descriptors, inodes, extents, directories, and requested file contents.

The useful files were:

```text
/pyz/exfil
/secure_cb/serpent_source.zip
/secure_cb/Cargo.lock
/secure_cb/Cargo.toml
/secure_cb/serpent_db
/secure_cb/src/main.rs
```

`serpent_db` is a statically linked Rust/SQLCipher command-line application.
The source code made its security design very clear:

```rust
const DB_PATH: &str = "/tmp/serpent.db";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const SALT: &[u8] = b"serpent_secure_salt_2026";
```

It derives a 32-byte key from the current boot ID using Argon2id:

```rust
Params::new(262144, 4, 4, Some(32))
```

Those values mean:

```text
memory cost = 262144 KiB
iterations  = 4
parallelism = 4
output      = 32 bytes
```

That derived key encrypts both:

1. the SQLCipher database, and
2. values placed in the Linux kernel keyring with ChaCha20-Poly1305.

This is why the memory dump is essential: the key is tied to the boot session.

---

## 5. Recovering flag part 1 from the SQLCipher database

### Deriving the boot-bound key

The active boot ID appears in journal data inside RAM:

```text
_BOOT_ID=710d1eb09a774c9ca148a8dd002d8755
```

Restored to its normal UUID form:

```text
710d1eb0-9a77-4c9c-a148-a8dd002d8755
```

Using the source-code parameters:

```python
from argon2.low_level import hash_secret_raw, Type

key = hash_secret_raw(
    b"710d1eb0-9a77-4c9c-a148-a8dd002d8755",
    b"serpent_secure_salt_2026",
    time_cost=4,
    memory_cost=262144,
    parallelism=4,
    hash_len=32,
    type=Type.ID,
)

print(key.hex())
```

The derived key is:

```text
4af1975878abc3db67aa68d510f848d277f2854fb5cf9ac92906c23a769e46e4
```

### Carving `/tmp/serpent.db` from the page cache

The database was stored in `/tmp`, not on the encrypted drive. I recovered it
from the Linux page cache:

1. Search memory for `serpent.db`.
2. Identify the containing `struct dentry`.
3. Follow `d_inode`.
4. Follow `i_mapping` to the inode's `address_space`.
5. Decode the `xarray` holding the cached pages.
6. Convert the three `struct page` pointers into physical page addresses.

The inode reported a size of:

```text
0x3000 = 12288 bytes
```

Its xarray contained three consecutive pages. Their PFNs were:

```text
0x362bc
0x362bd
0x362be
```

Reading those physical pages in order produced the complete 12 KB encrypted
SQLCipher database.

For convenience, I queried it using the recovered static application. I patched
the embedded 31-byte boot-ID path to another 31-byte path:

```text
/proc/sys/kernel/random/boot_id
/tmp/BBBBBBBBBBBBBBBBBBBBBBBBBB
```

I placed the captured boot ID in the second path and copied the carved database
to `/tmp/serpent.db`. The application then derived the correct key by itself:

```bash
./serpent_db_patched list
```

Output:

```text
Records:
 - part_1
```

Then:

```bash
./serpent_db_patched read part_1
```

Output:

```text
Value for 'part_1': HTB{v0l4t1l3_1uk52_d3crypt10n_
```

So:

```text
part 1 = HTB{v0l4t1l3_1uk52_d3crypt10n_
```

---

## 6. Recovering flag part 2 from the kernel keyring

Searching RAM revealed a second key description:

```text
keyring:part_2@serpent
```

Following its pointer to another kernel `struct key`, and then to its
`user_key_payload`, recovered this Base64 string:

```text
vFq7uwx/2Zet+LsG3dpjbe1cJdfbykcWbitZs22pUysEUQREdJTNkc6jDDnYOHEHhSDFQw==
```

The Rust source says keyring values are stored as:

```text
Base64(nonce || ChaCha20Poly1305 ciphertext || tag)
```

The nonce is the first 12 decoded bytes, and the same Argon2-derived boot key is
used for ChaCha20-Poly1305:

```python
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

encoded = (
    "vFq7uwx/2Zet+LsG3dpjbe1cJdfbykcWbitZs22pUysEUQREdJTNkc6j"
    "DDnYOHEHhSDFQw=="
)

blob = base64.b64decode(encoded)
key = bytes.fromhex(
    "4af1975878abc3db67aa68d510f848d2"
    "77f2854fb5cf9ac92906c23a769e46e4"
)

plaintext = ChaCha20Poly1305(key).decrypt(
    blob[:12],
    blob[12:],
    None,
)

print(plaintext.decode())
```

Output:

```text
w1th_k3rn3l_k3yr1ng_4nd_
```

So:

```text
part 2 = w1th_k3rn3l_k3yr1ng_4nd_
```

---

## 7. Decrypting the WireGuard capture

The PCAP contains:

1. a WireGuard handshake,
2. WireGuard transport packets,
3. an inner TCP connection from `10.0.0.2` to `10.0.0.1:9999`.

The client WireGuard index was visible in the capture. Searching memory for
that index located the active `wg_peer`, then its current keypair.

The live session keys were:

```text
10.0.0.2 -> 10.0.0.1
2d3d193f3889d53e9d1788e2fb42589d2b5390a2160c061baa6529e6da1da21c

10.0.0.1 -> 10.0.0.2
953c534a5e6402ff3ed260cc23383beba5dccb31adb4119429bd9c54f3e8a42e
```

WireGuard transport messages use ChaCha20-Poly1305. Their nonce is:

```text
four zero bytes || little-endian 64-bit packet counter
```

A shortened decryptor looks like:

```python
from scapy.all import rdpcap, IP, IPv6
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import struct

send_key = bytes.fromhex(
    "2d3d193f3889d53e9d1788e2fb42589d"
    "2b5390a2160c061baa6529e6da1da21c"
)

recv_key = bytes.fromhex(
    "953c534a5e6402ff3ed260cc23383beba"
    "5dccb31adb4119429bd9c54f3e8a42e"
)

for packet in rdpcap("capture.pcapng"):
    if not packet.haslayer("UDP"):
        continue

    wireguard = bytes(packet["UDP"].payload)
    if len(wireguard) < 32:
        continue

    msg_type, receiver_index, counter = struct.unpack_from(
        "<IIQ", wireguard
    )
    if msg_type != 4:
        continue

    key = send_key if packet[IP].src == "192.168.56.101" else recv_key
    nonce = b"\0" * 4 + struct.pack("<Q", counter)

    plaintext = ChaCha20Poly1305(key).decrypt(
        nonce,
        wireguard[16:],
        None,
    )
```

All 44 transport messages decrypted successfully.

### Reassembling the inner TCP stream

Inside WireGuard was a normal TCP session:

```text
10.0.0.2:56192 -> 10.0.0.1:9999
```

The application protocol is wonderfully simple:

```text
4-byte big-endian payload length
encrypted payload
```

The length field was:

```text
00 00 6b 85 = 27525 bytes
```

One small trap: WireGuard pads inner packets to a multiple of 16 bytes. Scapy
represents those extra bytes as a `Padding` layer. Reassembling
`bytes(packet[TCP].payload)` accidentally includes some padding. I used only
`packet[Raw].load`, sorted by TCP sequence number.

The result was exactly:

```text
4-byte length + 27525-byte payload
```

---

## 8. Reversing the exfiltration program

`/pyz/exfil` is a PyInstaller executable. Listing its archive showed a Python
module named `exfil`:

```bash
pyi-archive_viewer -l extracted_disk/pyz/exfil
```

I extracted its marshalled Python code and disassembled it with Python 3.13.
The important function reconstructs to:

```python
def encrypt_and_wipe_plaintext(buf):
    key = hashlib.sha256(HARDCODED_SECRET).digest()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, buf, None)
    secure_wipe(address_of(buf), len(buf))
    return nonce + ciphertext
```

The secret and source file were hardcoded:

```python
HARDCODED_SECRET = b"https://www.youtube.com/watch?v=oHafFDkFgeg"
FILE_PATH = "/root/dummy.pdf"
```

Therefore the AES-256-GCM key is:

```text
SHA256("https://www.youtube.com/watch?v=oHafFDkFgeg")
```

Which equals:

```text
867e6afb0abf40041abc188c0a5787b1d71dcc2fe55b8548521216ee9c27e9c8
```

The network payload is:

```text
12-byte nonce || AES-GCM ciphertext || 16-byte tag
```

Decryption:

```python
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

payload = open("wireguard_payload.bin", "rb").read()

key = hashlib.sha256(
    b"https://www.youtube.com/watch?v=oHafFDkFgeg"
).digest()

plaintext = AESGCM(key).decrypt(
    payload[:12],
    payload[12:],
    None,
)

open("exfil_plain.pdf", "wb").write(plaintext)
```

The result is a valid two-page PDF:

```bash
file exfil_plain.pdf
pdftotext -layout exfil_plain.pdf -
```

Near the end of the document:

```text
part_3: w1r3gu4rd_3xf1l_brrr_brrr_brrr!!}
```

So:

```text
part 3 = w1r3gu4rd_3xf1l_brrr_brrr_brrr!!}
```

---

## 9. Joining the fragments

The three pieces are:

```text
HTB{v0l4t1l3_1uk52_d3crypt10n_
w1th_k3rn3l_k3yr1ng_4nd_
w1r3gu4rd_3xf1l_brrr_brrr_brrr!!}
```

Final flag:

```text
HTB{v0l4t1l3_1uk52_d3crypt10n_w1th_k3rn3l_k3yr1ng_4nd_w1r3gu4rd_3xf1l_brrr_brrr_brrr!!}
```

---

## Takeaways

The challenge chains together several ideas, but each one is logical:

- An unlocked encrypted drive must have its real key somewhere in RAM.
- A boot-bound secret is recoverable if both the boot ID and encrypted data
  survive in memory.
- Linux keyring values are only as safe as the process key used to encrypt
  them.
- Captured WireGuard traffic can be decrypted if its live session keys are
  recovered.
- Securely wiping one plaintext buffer does not help if the encryption logic
  and resulting ciphertext let an investigator reproduce the decryption.

The hardest part was not any single cipher. It was carefully following the
links between kernel structures, disk metadata, application source, and
network packets without losing a few bytes to an offset or padding mistake.
