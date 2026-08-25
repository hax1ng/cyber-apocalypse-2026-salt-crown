# Overstrike — Writeup

**Category:** Mobile  
**Event:** Cyber Apocalypse CTF 2026: The Salt Crown  
**Flag:** `HTB{0v3rstr1k3_r3cut_th3_w0rld_s34l_by_f0rg1ng_th3_mark}`

---

## The story (skip if you only want the tech)

The Signet is shattered. House Vaultrune has been quietly re-cutting marks — forging authority so the lie looks like official record. You play Elric under Crownspire. The old vow-stones of the Ash-Vault will not bridge the fire-rift for any ordinary mark. They only answer to the **true seal**. To read the Registry (and get the flag), you have to forge a seal so good the world itself cannot tell it from genuine.

That lore is not just fluff — the game code is basically that plot in C#.

---

## What you get

One fat APK: `Overstrike.apk` (~200 MB).

First instinct might be “Android reverse, dig through Java/Kotlin.” That’s only half true. Open the APK as a zip and you immediately see:

- `lib/*/libgodot_android.so` — this is a **Godot** game
- Mono / .NET stuff under `assets/.godot/mono/publish/`
- A small game assembly: **`Overstrike.dll`**

So this is not a classic Android app challenge. It’s a Godot game shipped for Android, with the interesting logic written in **C#**. The Java layer is mostly the Godot shell. The puzzle lives in the DLL.

---

## Finding the real code

Extract and decompile the game DLL (ILSpy / `ilspycmd` works fine):

```text
assets/.godot/mono/publish/x86_64/Overstrike.dll
assets/.godot/mono/publish/arm64/Overstrike.dll   # same game logic
```

Decompilation is noisy because Godot injects a ton of glue methods (`GetGodotMethodList`, property reflection, etc.). Mentally filter that out and look at the class names:

| Script | Role |
|--------|------|
| `GameState` | Holds your mark, computes the world seal, unseals the Registry |
| `BridgeBuilder` | Builds the vow-stone bridge; only fully works with the true seal |
| `MarkPickup` | Picking up marks adds to `CarriedMark` |
| `Archive` | Shows the Registry text when you reach it |
| `Hud` | Displays mark / seal / “vow-stones are dark…” status |

Once you read those, the whole challenge clicks.

---

## How the game “security” works

### Marks and seals

Every frame, roughly:

```csharp
WorldSeal = Mix(CarriedMark);
```

And “are we legit?” is just:

```csharp
WorldIsAligned => WorldSeal == TrueSeal;
// TrueSeal = 15682021040575554950  (0xD9A1BB0CABB52586)
```

So:

1. You carry a 64-bit number (`CarriedMark`).
2. It gets scrambled by a function `Mix`.
3. If the result equals a hardcoded **true seal**, the bridge lights up and the world accepts you.

The HUD even tells you this in plain English: either *“The vow-stones answer. Cross the rift.”* or *“The vow-stones are dark. Your mark is not the true seal.”*

### What `Mix` actually is

`Mix` is the classic **SplitMix64** finalizer (same constants you see everywhere in PRNGs):

```text
x  += 0x9E3779B97F4A7C15
x   = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
x   = (x ^ (x >> 27)) * 0x94D049BB133111EB
return x ^ (x >> 31)
```

Important property for solvers: **this is bijective**. Every seal comes from exactly one mark, and you can run the math backwards. You do **not** need to brute force a 64-bit space.

### The bridge

`BridgeBuilder` rebuilds tiles from the current seal. When the seal equals `TrueSeal`, tiles align into a proper path. Otherwise the stones are wrong / incomplete. Flavor text = collision shapes.

### Where the flag hides

`GameState.UnsealRegistry()` does the actual flag reveal. In short:

1. Take `SHA256` of your `CarriedMark` (as little-endian 8 bytes). Call that the key material.
2. Expand it into a keystream: for counter `0, 1, 2, ...`, hash `SHA256(key || LE32(counter))`.
3. XOR that stream against a hardcoded ciphertext blob `SealedRecord`.
4. Print whatever printable ASCII falls out (non-printable becomes `▯`).

The Archive UI just shows:

```text
THE REGISTRY

<whatever UnsealRegistry returns>
```

So if you stand in the archive with the correct mark, you *see* the flag in-game. Or you skip the emulator entirely and decrypt offline. Offline is faster.

---

## Solving it without playing the game

### Step 1 — Invert `Mix`

We need `CarriedMark` such that:

```text
Mix(CarriedMark) == TrueSeal
```

Invert SplitMix64 (undo the xor-shifts, modular-multiply by the inverses of the odd constants, subtract the golden-ratio constant). Result:

```text
CarriedMark = 0xD7CAAD24DD98B676
            = 15549431037298259574
```

Sanity check: run `Mix` forward again → gets `0xD9A1BB0CABB52586` = `TrueSeal`. Good.

### Step 2 — Pull `SealedRecord` out of the DLL

In the assembly metadata, `SealedRecord` is initialized from a static byte array in `<PrivateImplementationDetails>` (size **56**). The other static array (size 40) is just the small mark values used as pickups in the level (`1, 2, 3, 5, 7`) — red herring for “maybe I just collect enough marks.”

Those tiny pickups only add tiny integers. They will **never** reach `0xD7CAAD24DD98B676` by normal play. That’s the joke: you must forge the mark yourself, the same way the forgers do — not grind collectibles.

### Step 3 — Decrypt

Pseudo-Python:

```python
import struct, hashlib

carried = 0xD7CAAD24DD98B676
sealed = bytes.fromhex(
    "0d563344126e440f363dec5e87cad5b60401b6b596e4b87e"
    "79e0ecdc075299fbb36800572022033ca6607c32fd1f7cb3"
    "dc9d7873132f600b"
)

key = hashlib.sha256(struct.pack("<Q", carried)).digest()
out = bytearray()
i = block = 0
while i < len(sealed):
    h = hashlib.sha256(key + struct.pack("<I", block)).digest()
    for b in h:
        if i >= len(sealed):
            break
        out.append(sealed[i] ^ b)
        i += 1
    block += 1

print(out.decode())
```

Output:

```text
HTB{0v3rstr1k3_r3cut_th3_w0rld_s34l_by_f0rg1ng_th3_mark}
```

Which literally says what you did: overstrike / re-cut the world seal by forging the mark.

---

## Could you solve it “in character”?

Sure, if you enjoy suffering:

1. Run the APK in an emulator.
2. Use a memory editor / Frida / Godot debugger to set `GameState.CarriedMark` to `0xD7CAAD24DD98B676`.
3. Watch the HUD flip to “vow-stones answer.”
4. Walk the bridge, enter the archive, read the Registry.

That’s a valid mobile dynamic path. Static inversion of `Mix` + offline XOR decrypt is the same crypto, zero walking required.

---

## Mental model for beginners

Think of it like a padlock with a weird combination system:

1. **Mark** = the combination you hold.
2. **Mix** = a blender that turns your combination into a seal number (always the same way, reversible if you know the blender).
3. **True seal** = the one number the vault likes (hardcoded).
4. **Registry ciphertext** = a diary locked with a key derived from your mark via SHA-256.
5. Normal pickups = loose pennies. Forged mark = the exact serial the vault was cut for.

The challenge is teaching a real idea: **integrity checks that only compare a hash/transform of a secret, without proving you “earned” that secret**, are just “find the preimage (or invert the transform).” Here the transform was intentionally invertible, so forging is clean math.

---

## File map (if you redo this later)

```text
Overstrike.apk
├── classes.dex / AndroidManifest.xml     # Godot Android wrapper (boring)
├── lib/*/libgodot_android.so             # engine
└── assets/.godot/mono/publish/*/
    └── Overstrike.dll                    # ← all challenge logic
```

Key constants:

| Name | Value |
|------|--------|
| `TrueSeal` | `0xD9A1BB0CABB52586` |
| Forged `CarriedMark` | `0xD7CAAD24DD98B676` |
| `SealedRecord` length | 56 bytes |
| KDF | `SHA256(LE64(mark))` then counter-mode SHA256 XOR |

---

## Flag

```text
HTB{0v3rstr1k3_r3cut_th3_w0rld_s34l_by_f0rg1ng_th3_mark}
```

---

## Takeaways

- **Mobile ≠ always Java.** Open the APK; if you see Godot/Unity/Flutter, follow the real runtime.
- Lore in HTB challenges often mirrors variable names. “True seal,” “mark,” “registry,” “forge” were all sitting in `GameState`.
- Recognize SplitMix64 / similar mixers — if you know they’re reversible, you skip a bad day of brute force.
- Ciphertext in a static array + “decrypt with player state” is a common CTF pattern; dump the blob, reimplement the few lines of crypto, win.

You didn’t need to bridge the fire-rift by hand. You just cut a better Signet.
