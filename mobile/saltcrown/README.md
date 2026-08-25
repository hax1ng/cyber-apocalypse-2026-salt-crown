# SaltCrown

**Category:** Mobile | **Difficulty:** Hard | **Flag:** `HTB{p3rf3ct_f4c3_wr0ng_sp1n3}`

## TL;DR

A Godot 4.7 + C# Android game hides the flag behind a two-layer lock: the game's C# logic XOR-decrypts a sealed 24-byte blob using a "measured" signature, and that signature is built from phase buckets produced by a **stripped native GDExtension** (`.so` file). We reverse the native PRNG from `objdump` disassembly, reimplement it in Python, derive the five engaging phase buckets, and feed them through the C# logic to unseal the flag.

## What We're Given

`SaltCrown.apk` — a 202 MB Android application. The challenge description frames it as a puzzle game where you play Elric Ashspar, an engineer who must "break the march" by making the city bell's counterfeit strike-plate fail under repetition. That flavor is a real hint, not just decoration.

Unpacking the APK (it's just a ZIP) reveals the core pieces:

| Path | What it is |
|------|-----------|
| `assets/.godot/mono/publish/x86_64/SaltCrown.dll` | Managed C# game logic (PE32+ / Mono .NET) |
| `lib/x86_64/libashvault.android.template_release.x86_64.so` | Native GDExtension, ELF64, **stripped** |
| `assets/rubbings/ashvault.dat` | 256-byte binary blob fed to the native function |
| `assets/native/ashvault.gdextension` | GDExtension manifest, declares entry `saltcrown_library_init`, min Godot 4.7 |

The managed DLL is the easy part — decompile it with ILSpy or dotPeek and you get clean C#. The `.so` is where it gets interesting.

## Initial Recon

**Decompiling the DLL.** Running the DLL through a .NET decompiler gives us the `SaltCrown.Mechanism` namespace with four key classes:

- `SaltCrownSpec` — contains `Measure`, `Unseal`, and `Mix`. This is where the flag comes out.
- `Tolerances` — pure geometry: choke positions, half-widths, which chokes physically "bite."
- `WearLattice` — the bridge. It instantiates the native `AshVault` GDExtension class and calls `admit_bucket(rubbing_bytes, choke_index)`.
- `StrikePlate` — the narrative hook. Tracks fatigue accumulation and emits a `Fractured` signal when the plate fails. **It looks important because of the flavor text, but it does not contain the flag.** This is one dead end that's easy to fall into.

**Checking the native library.** The `.so` is stripped — no symbol table, no function names. `file` confirms it's an Android NDK r27 x86-64 binary. We can't just call `nm` and find `admit_bucket`. Time for `objdump`.

```bash
objdump -d lib/x86_64/libashvault.android.template_release.x86_64.so | less
```

The disassembly is dense but two things jump out immediately: a cluster of distinctive hex constants (`0x811c9dc5`, `0x1000193`, `0x85ebca77`, `0xc2b2ae3d`) and a loop structure with bit rotations. Those first two constants are the FNV-1a offset basis and prime — a hash algorithm's fingerprints. The other two are from MurmurHash3's avalanche mixing step. Now we know we're looking at a custom PRNG, not a standard one.

```bash
objdump -d lib/x86_64/libashvault.android.template_release.x86_64.so \
  | grep -iE '0x1000193|0x811c9dc5|0x85ebca77|0xc2b2ae3d'
```

All four constants appear at the expected instruction offsets. This is enough to reconstruct the algorithm.

## The Vulnerability / Trick

There's no traditional "vulnerability" here — this is a reverse engineering challenge. The trick is that the flag lives inside `SaltCrownSpec.Unseal`, locked behind a 32-bit key called `measured`. Computing `measured` requires phase buckets from the native PRNG, and understanding which chokes produce those buckets requires working through the geometry in `Tolerances.cs`.

Here's the full chain:

1. **Geometry decides the loop range.** `Tolerances.ChokeZ(i) = 14 - 6*i` gives eight choke positions. A choke only "seats" (engages) if `HalfWidthAt(ChokeZ(i)) <= MaxBitingHalfWidth (8.1)`. Working through the lerp math:

   | Choke | z | HalfWidth | Engages? |
   |-------|---|-----------|----------|
   | 0 | 14 | 9.500 | NO |
   | 1 | 8 | 9.022 | NO |
   | 2 | 2 | 8.544 | NO |
   | **3** | **-4** | **8.067** | **YES** |
   | **4** | **-10** | **7.589** | **YES** |
   | **5** | **-16** | **7.111** | **YES** |
   | **6** | **-22** | **6.633** | **YES** |
   | **7** | **-28** | **6.156** | **YES** |

   Only chokes 3 through 7 engage. That's the loop range for building `measured`.

2. **The native PRNG produces a "phase bucket" for each choke.** `WearLattice.AdmitBucket(choke)` calls out to native `AshVault::admit_bucket(rubbing_bytes, choke)`. The native routine is a two-phase custom PRNG:

   - **Init phase:** For each of 64 "seats," run an FNV-1a-ish loop over the 256-byte rubbing (seed `0x811c9dc5`, prime `0x1000193`) to produce 64 × uint32 state lanes.
   - **Mix phase:** Run `0x1000` (4096) rounds. Each round updates all 64 lanes using left rotations (rol 7, rol 27, rol 13), MurmurHash3-style multiply-xorshift constants (`0x85ebca77`, `0xc2b2ae3d`), and a per-round step constant of `0x9e3779b9` (the golden ratio — seen everywhere in hash mixing).
   - **Output:** `admit_bucket(choke)` picks two lanes `a = (7*choke+3)&63` and `b = (23*choke+41)&63`, computes `x = rol(state[b], 11) ^ state[a]`, and returns `((x>>5)^(x>>13)) & 0xff`.

3. **`SaltCrownSpec.Measure` folds the buckets into a 32-bit signature.** Starting from the FNV offset basis `0x811c9dc5`, it applies `Mix(acc, chokeIndex)` then `Mix(acc, bucket)` for each engaging choke. `Mix` is an FNV-1a step followed by an Mx3 avalanche: `h^=v; h*=16777619; h^=h>>15; h*=2246822519; h^=h>>13`.

4. **`SaltCrownSpec.Unseal(measured)` decrypts the flag.** It XORs the 24-byte `SealedSpec` (baked into the DLL at file offset `0x1a490`) with a keystream where byte `i` is `(Mix(num, i) >> 24)` with `num` chained.

The beauty of this design: `measured` is a single 32-bit seed that depends on all five buckets. One wrong bucket byte scrambles the entire 24-byte keystream to garbage. If we get clean ASCII out, every bucket was correct.

## Building the Exploit

The solve is pure Python — no need to run the actual app.

**Step 1: Reconstruct the native PRNG.**

We load the 256-byte rubbing and initialize 64 state lanes using the FNV-1a-ish loop we read from the disassembly:

```python
data = Path('analysis_extract/assets/rubbings/ashvault.dat').read_bytes()
state = []
for seat_i in range(64):
    h = 0x811c9dc5
    even_len = len(data) & ~1
    for k in range(0, even_len, 2):
        h = ((h ^ (data[k] + seat_i)) * 0x1000193) & MASK
        t = (data[k+1] + seat_i) ^ h ^ (h >> 11)
        q = (t * 0x1000193) & MASK
        h = q ^ (q >> 11)
    state.append(h & MASK)
```

The loop processes pairs of rubbing bytes, mixing the seat index in as a per-lane offset. This is the non-obvious part that required careful reading of the x86-64 disassembly — the pair-at-a-time structure and the intermediate `t` variable are what distinguish this from vanilla FNV-1a.

**Step 2: Run the 4096 mixing rounds.**

```python
round_constant = 0
for rnd in range(0x1000):
    new = []
    for j in range(64):
        s = rol32(state[(j-1) & 63], 7) ^ rol32(state[(j+1) & 63], 27) ^ state[j]
        d = (s * 0x85ebca77 + round_constant + j) & MASK
        s2 = d ^ (d >> 15)
        d2 = (s2 * 0xc2b2ae3d) & MASK
        v = rol32(state[j], 13) ^ d2
        new.append((v ^ (v >> 16)) & MASK)
    state = new
    round_constant = (round_constant + 0x9e3779b9) & MASK
```

Each lane mixes with its neighbors (borrowing from the previous and next lane), applies MurmurHash3 constants, and advances the round counter by the golden ratio step. This is a fairly beefy PRNG — 4096 rounds of 64-lane mixing — which is why someone spent time implementing it natively instead of in C#.

**Step 3: Implement `admit_bucket` and compute all eight buckets.**

```python
def admit_bucket(choke):
    a = (7 * choke + 3) & 63
    b = (23 * choke + 41) & 63
    x = rol32(state[b], 11) ^ state[a]
    return ((x >> 5) ^ (x >> 13)) & 0xff

buckets = [admit_bucket(i) for i in range(8)]
# [149, 84, 104, 178, 26, 6, 101, 234]
```

**Step 4: Replicate `Measure` over the engaging chokes (3..7).**

```python
def mix(h, v):
    h = (h ^ v) & MASK
    h = (h * 16777619) & MASK
    h = (h ^ (h >> 15)) & MASK
    h = (h * 2246822519) & MASK
    h = (h ^ (h >> 13)) & MASK
    return h

measured = 2166136261  # 0x811c9dc5, the FNV offset basis (Unmeasured)
for choke in range(3, 8):
    measured = mix(measured, choke)
    measured = mix(measured, buckets[choke])
# measured = 0x75f944d2
```

**Step 5: Unseal the flag.**

```python
sealed = bytes.fromhex('75c9ab6b9a53cfbf1fe97e4a939425e029cf87a9c280dedc')
out = []
num = measured
for i, c in enumerate(sealed):
    num = mix(num, i)
    out.append(c ^ (num >> 24))
print('HTB{' + bytes(out).decode('ascii') + '}')
```

We verified the sealed bytes are present in the DLL:

```python
import binascii
d = open('assets/.godot/mono/publish/x86_64/SaltCrown.dll', 'rb').read()
n = binascii.unhexlify('75c9ab6b9a53cfbf1fe97e4a939425e029cf87a9c280dedc')
print(hex(d.find(n)))  # 0x1a490
```

The full solver is in `solve.py`.

## Running It

```
$ python3 solve.py
buckets: [149, 84, 104, 178, 26, 6, 101, 234]
measured: 0x75f944d2
flag: HTB{p3rf3ct_f4c3_wr0ng_sp1n3}
choke 3: z= -4, bucket=178, phase=0.695313
choke 4: z=-10, bucket= 26, phase=0.101563
choke 5: z=-16, bucket=  6, phase=0.023438
choke 6: z=-22, bucket=101, phase=0.394531
choke 7: z=-28, bucket=234, phase=0.914063
```

Clean thematic leetspeak ASCII: "p3rf3ct f4c3 wr0ng sp1n3" — perfect face, wrong spine. A counterfeit bell's strike plate has the right surface finish (the face) but the wrong internal structure (the spine) — it looks right but fails under repetition. The challenge author went all the way with the metallurgy metaphor.

## Key Takeaways

**Flavor text is often the first clue.** "Counterfeits fail under repetition" directly described the `StrikePlate.Endure()` fatigue accumulation mechanic, which in turn signals that the flag is revealed by *exercising* the mechanism, not by finding a hardcoded string.

**The obvious class isn't always the right one.** `StrikePlate` sounds important — it's in the description, it has dramatic signal names (`Fractured`), and the narrative is built around it. But it's just the game-mechanic wrapper. The real flag logic is in `SaltCrownSpec`, a much quieter class.

**GDExtensions are the new plugin DLLs.** Godot 4's GDExtension system lets game devs ship compiled native libraries that expose classes and methods to GDScript and C# as if they were built-in engine types. From a reversing perspective: decompile the C# for high-level logic, then look at the `.gdextension` manifest to find native entry points, then `objdump`/`ghidra` the `.so` for the actual implementation.

**FNV-1a constants are a fingerprint.** If you see `0x811c9dc5` (the FNV offset basis) or `0x1000193` (the FNV prime) in disassembly, you're looking at some variant of FNV hashing — even if it's been customized. Similarly, `0x9e3779b9` is the 32-bit golden ratio constant and almost always indicates a mixing/avalanche step borrowed from one of the MurmurHash or xxHash family.

**One wrong byte breaks everything.** The `measured` value is the only input to the keystream. If even one of the five phase buckets was wrong, the 24-byte output would be garbage. Getting clean ASCII out on the first correct run is the decisive self-validation — and a deeply satisfying one.
