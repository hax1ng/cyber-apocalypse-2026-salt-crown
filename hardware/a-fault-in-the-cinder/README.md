# A Fault in the Cinder — Writeup

**Event:** Cyber Apocalypse CTF 2026: The Salt Crown  
**Category:** Hardware  
**Flag:** `HTB{a_f4ls3_n0t3_0p3ns_th3_tru3_s34l}`

---

## The story (what you’re actually doing)

There’s a fancy locked box — a **Cinderbound custody coffer** — holding a sealed political receipt: proof of what the Black Heir plans to do to House Suncourt. You can’t smash it open. Breaking the shell **burns the record**. So the job is sneakier:

1. Pretend to be a Vaultrune auditor just long enough for the box to believe you.  
2. Catch the moment it still says “no,” and **fault-inject** past that check.  
3. Listen on the **internal SPI bus** while the secure element hands the encrypted record to firmware that now thinks it’s allowed to unseal.  
4. Decrypt that session yourself and read the custody writ — flag included.

In plain terms: **fake the badge shape, skip the “access denied” branch with a glitch, sniff the private conversation, finish the crypto the firmware was going to do.**

---

## What the box is made of

| Piece | Job |
|--------|-----|
| **Boot ROM** (`cinder_boot.elf`) | Cortex-M3 @ 24 MHz. Verifies firmware, talks to the ward, decides recovery vs production. |
| **Secure element (“ward”)** | Holds the sealed record and answers on internal SPI. Opcodes like challenge, ticket verify, open session, unseal, read FIFO. |
| **Recovery firmware** | After an authorized recovery boot, opens a “factory session,” unseals, and pulls the record. |
| **Bench** | Remote **rig** (strap/glitch/power), **logic analyzer** (VCD of internal SPI), **service console** (ticket + challenge). |

You’re never meant to get a valid ECDSA recovery ticket. The challenge is to **make the MCU ignore the ward’s “no”** and still run the unseal path.

---

## Step 1 — Learn the ritual (offline reverse)

### Recovery path in the boot ROM

On a recovery strap, if the image’s security counter is behind the ward’s NV counter, the ROM asks for a **service signet**: a 144-byte `RCVT` ticket.

The ROM only **struct-checks** the ticket (magic `RCVT`, version 1, flags 0, right length). Then it ships the blob to the ward with `VERIFY_RECOVERY_TICKET` (`0x13`).

- Valid ticket → status 0.  
- Anything else well-formed but wrong → same **`AUTH_DENIED`** (status 1).  
- Garbage envelope → ward never even answers (no trigger).

So for the glitch we **forge a pretty envelope and a bad signature**. The ward will deny us; we only need that deny frame so the fault rig can trigger.

### The gate we glitch

After verify returns, roughly:

```text
build a permission flag from (image vs NV counter) and (verify OK?)
if permission == 0:
    fail_and_halt          ← beq to fail @ 0x118   *** omit this instruction ***
else:
    EXTEND_BOOT_PCR
    LOCK_MEASUREMENT
    jump into recovery app
```

If we **omit that fail branch**, the CPU falls through into “authorized” behavior even though the ward said no. The ward still thinks auth failed — but it still speaks factory-session opcodes when the app asks. That’s enough: the ciphertext shows up on the wire.

### Challenge-dependent delay (don’t blind-sweep)

Between verify return and the fail branch, the ROM spins a tiny loop based on the challenge:

```text
N = (challenge[0] ^ challenge[15]) & 0x1f
# ~8 cycles per count, plus fixed work
delay = D_drv + window = 221 + (8*N + 33) = 254 + 8*N
```

Trigger: first response byte of VERIFY is `0x13` (with a bad ticket this *is* AUTH_DENIED).  
Pulse width: about **10** ticks (single-instruction omit band ~6–16).

### Ticket we stage

```text
RCVT | ver=1 | flags=0 | 138 zeros
```

Base64 that, send `TICKET …` on the service port for the next boot.

---

## Step 2 — Run the glitch (live)

Rough recipe against the team bench:

```text
STRAP RECOVERY
RESET RIG
# learn CHALLENGE from service offer → N, delay = 254 + 8*N
TICKET <forged RCVT>
TRIGGER BUS SE PATTERN 13 MASK ff
GLITCH DELAY <delay> WIDTH 10
CAPTURE ARM INTERNAL_SPI
POWER CYCLE
```

Good run looks like:

- Rig: **TRIGGERED**, capture id  
- SPI: VERIFY **status 1**, then **EXTEND / LOCK / OPEN / UNSEAL / GET_STATUS=data ready / READ_FIFO × 19**

If you only see AUTH_DENIED and halt, timing is off by a few ticks. If you never trigger, the ticket wasn’t well-formed enough for the ward to answer.

We saved captures as `glitch.vcd` / `glitch3.vcd` and decoded them into SE transactions (opcode, status, payload).

---

## Step 3 — What’s on the bus after success

Typical live sequence (compressed):

| Op | Meaning | Live notes |
|----|---------|------------|
| `0x10` STARTUP | Wake ward | ok |
| `0x11` READ_NV_COUNTER | e.g. **5** | recovery image counter is **2** → ticket path required |
| `0x12` GET_RECOVERY_CHALLENGE | 16 random bytes | drives glitch delay |
| `0x13` VERIFY | **status 1** AUTH_DENIED | glitch target edge |
| `0x14` / `0x15` | EXTEND + LOCK PCR | MCU still “authorized” |
| `0x20` OPEN_FACTORY_SESSION | host sends 16-byte nonce; ward returns **magic ‖ sess** | session material |
| `0x21` UNSEAL | empty on the wire | status 0 |
| `0x22` READ_FIFO | chunks of sealed record | 19 chunks, CRC clean |

Each FIFO payload looks like:

```text
magic_u32le | idx_u16 | total_u16 | size_u16 | ciphertext[size] | mac[16]
```

Often `size = 32`, last chunk shorter. **Don’t drop the MAC** when reassembling — `plen` is 10 + size + 16.

Factory capture (`factory_service.sr`) is the same dance with a **valid** ticket and a short **demo** record (5 chunks). Live is longer and holds the real writ + flag.

---

## Step 4 — Decrypt the factory session (the “hard” part)

Recovery firmware does not print the flag in clear on the service console. The record rides an **AEAD-like construction** over the session key:

1. **KDF** (`0x200021c0` in recovery):  
   `session_key = HMAC-SHA256(KEY_ROOT, derived8 || sess || bswap32_words(c32) || host_nonce)`

2. **MAC** (`0x20002258`):  
   `HMAC-SHA256(session_key, magic||idx_low_byte || ciphertext)[:16]`

3. **Keystream**: for each 32-byte block,  
   `HMAC-SHA256(session_key, "RESPONSE" || magic_u32 || idx_lo || block_index_u16 || 0x00 || 0x00)` (17-byte label), XOR into CT.

`KEY_ROOT` sits in the recovery image (~offset `0xa8e`).  
`derived8` is a fixed mix of two constants at `0xbb8` (`0x7f4a7c15`, `0x9e3779b9`).

### The trap: factory vs live `c32`

Offline, the **factory** capture decrypts cleanly if you set:

```text
c32 = bytes(range(32))   # 00 01 02 ... 1f
```

That’s the stub / golden-model path. Same formula on **live** SPI → **0/19 MACs**. Hours of wrong permutations later, the missing input is the boot measurement.

From TARGET.pdf + boot ROM (`~0x138`):

```text
M = SHA256(
      "CINDER-BOOT-v1"
   || kind_u8              # single byte from image header, not a full u32!
   || counter_le32
   || payload_size_le32
   || payload_sha256
)

BOOT_PCR = SHA256( 0x00 * 32 || M )   # one extend from all-zero PCR
```

**Live:** `c32 = BOOT_PCR`.  
**Factory demo:** `c32 = 0..31`.

Once you use PCR on a live capture, MACs hit **19/19** and the TLV plaintext falls out.

---

## Step 5 — What the record says

Decrypted custody object (TLV-ish) includes:

- Succession id: `custody-succession`  
- House: *House Suncourt of the Velvet Spider*  
- Registry / seal: `SEAL-CINDER-0001`  
- A nasty writ under Cassian’s hand (burn the ledgers, erase the house, …)  
- And the CTF flag field:

```text
HTB{a_f4ls3_n0t3_0p3ns_th3_tru3_s34l}
```

Title tracks: a false note (forged ticket + glitched gate) opens the true seal (PCR-bound factory session).

---

## End-to-end recipe (copy-paste mental model)

```text
1. Offline
   - Map fail branch @ 0x118 and delay = 254 + 8*N
   - Confirm factory AEAD with c32 = range(32)
   - Compute M and BOOT_PCR from recovery_image.bin

2. Live
   - Recovery boot → read CHALLENGE
   - Stage forged RCVT
   - Arm trigger 13 / glitch delay / width 10 / SPI capture
   - Power cycle → download VCD

3. Decrypt
   - Parse OPEN → host_nonce, sess
   - Parse all 0x22 frames → (hdr, ct, mac)
   - session_key = HMAC(KR, derived || sess || bswap(PCR) || hn)
   - Verify MACs, XOR RESPONSE keystream
   - Find HTB{...}
```

`solve.py` does offline self-test, remote glitch, and decrypt (tries PCR first, then range32 for factory).

---

## Why this works as a challenge design

- **Hardware angle:** single-instruction skip after a clean, challenge-dependent delay — real FI flavor without needing a chip on your desk.  
- **Protocol angle:** SE frames, CRC, FIFO chunking, sequence bytes.  
- **Crypto angle:** not “guess AES”; reverse a small HMAC-AEAD and notice **measurement binding** only shows up on the live ward.  
- **Story angle:** you never get a real auditor signet; you forge the *shape* of authority and steal the *instant* of trust.

---

## Files that matter

| File | Why |
|------|-----|
| `TARGET.pdf` | Opcodes, glitch model, measurement formula |
| `cinder_boot.elf` | Auth gate + timing + `M` construction |
| `recovery_payload.bin` / `recovery_image.bin` | KDF, AEAD, KEY_ROOT, image header for PCR |
| `factory_service.sr` | Known-good SPI + demo decrypt oracle |
| `solve.py` | Glitch client + decrypt |
| `flag.txt` | Final answer |

---

## Flag

```
HTB{a_f4ls3_n0t3_0p3ns_th3_tru3_s34l}
```

---

*Casual translation of the whole fight: the coffer only unseals for a measured, authorized recovery boot. We couldn’t pass crypto auth, so we glitched the CPU past the deny, recorded the private bus, and finished the same HMAC session the firmware uses — remembering that on the real ward the session is tied to the boot PCR, not the factory stub’s `0..31` pad.*
