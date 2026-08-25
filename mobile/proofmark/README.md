# Proofmark Writeup

## Challenge

**Category:** Mobile  
**App:** `proofmark.apk`

> Vaultrune's assay decides which seals are inherited and which were cut from a
> Signet shard. Elric only gets one strike, so we need to make his homemade ring
> look genuine.

## Short version

The APK is a small Godot game. The visible game logic is written in GDScript,
but the important verification code lives in a tiny native library named
`libproofmark.x86_64.so`.

The native verifier contains:

1. A hidden target state: `(83, 67, 55, 462)`.
2. A custom hash-like function that creates a “hallmark.”
3. An encrypted 28-byte certificate.

The public `reseal()` function deliberately corrupts the hallmark when given
the hidden state, so simply calling it is not enough. Reimplementing the
underlying algorithm *before* that corruption gives the real hallmark:

```text
0x71d3a101
```

Using that hallmark to decrypt the certificate produces:

```text
HTB{p3rf3ct_f4c3_tru3_sp1n3}
```

---

## 1. Looking inside the APK

An APK is basically a ZIP archive, so the first step was listing its contents:

```bash
unzip -l proofmark.apk
```

The interesting files were:

```text
assets/scripts/ForgeClient.gdc
assets/scripts/GameState.gdc
assets/scripts/WardCutter.gdc
lib/x86_64/libproofmark.x86_64.so
lib/arm64-v8a/libproofmark.arm64.so
```

The `.gdc` files are compiled Godot scripts. I recovered them with GDRE Tools:

```bash
gdre_tools.x86_64 --headless \
    --recover=proofmark.apk \
    --output=recovered
```

This gave readable `.gd` source files under `recovered/scripts/`.

---

## 2. Understanding the game state

`GameState.gd` stores three adjustable “wards,” plus a value called `bite`:

```gdscript
var wards: PackedInt32Array = PackedInt32Array([0, 0, 0])
var bite: int = 0
var hallmark: int = 0
```

Whenever a ward changes, `bite` is recalculated:

```gdscript
bite = wards[0] + wards[1] * 2 + wards[2] * 3
```

These four numbers are serialized as four little-endian 32-bit integers:

```gdscript
func snapshot() -> PackedByteArray:
    var buf := PackedByteArray()
    buf.resize(16)
    buf.encode_s32(0, wards[0])
    buf.encode_s32(4, wards[1])
    buf.encode_s32(8, wards[2])
    buf.encode_s32(12, bite)
    return buf
```

The snapshot is sent into the native library to create a hallmark:

```gdscript
hallmark = ForgeClient.reseal(snapshot())
```

At the anvil, both the snapshot and cached hallmark are submitted:

```gdscript
var result := ForgeClient.strike(
    GameState.snapshot(),
    GameState.hallmark
)
```

The result can be:

```text
0 = rejected state
1 = correct-looking state, but wrong hallmark
2 = accepted
```

The flag is only returned for result `2`.

---

## 3. The native verifier

`ForgeClient.gd` revealed the three methods exported by the native library:

```gdscript
_native.reseal(...)
_native.submit(...)
_native.certificate()
```

I loaded `libproofmark.x86_64.so` into Ghidra. The symbols were stripped, but
the library was tiny and the important functions were easy to identify by
following the wrappers for `reseal` and `submit`.

### Hidden target state

The beginning of `submit()` compares the submitted 16 bytes against a constant
stored at `.rodata + 0x30`:

```text
53 00 00 00
43 00 00 00
37 00 00 00
ce 01 00 00
```

Reading those as four little-endian integers gives:

```text
(83, 67, 55, 462)
```

In simplified form, the check is:

```c
if (state != (83, 67, 55, 462))
    return REJECT_STATE;
```

This cannot be entered through normal gameplay. The three wards are clamped
between `0` and `24`, and the fourth number normally has to be:

```text
ward0 + 2*ward1 + 3*ward2
```

The hidden state breaks both rules. That is our first clue that we are expected
to reverse the native assay instead of honestly filing the ring in the game.

---

## 4. Rebuilding the hallmark algorithm

The `reseal()` function runs a short program through a custom bytecode
interpreter. Once the bytecode is translated into normal pseudocode, it is much
less scary than it first appears.

The central mixing function is:

```python
def mix(x):
    x = ((x >> 16) ^ x) * 0x85EBCA6B & 0xFFFFFFFF
    x = ((x >> 13) ^ x) * 0xC2B2AE35 & 0xFFFFFFFF
    return ((x >> 16) ^ x) & 0xFFFFFFFF
```

The four integers are packed into 16 little-endian bytes. Starting with the
seed `0x53437277`, each byte is folded into the hallmark:

```python
x = 0x53437277

for byte in state:
    x ^= byte
    x = rol32(x, 5)
    x += 0x9E3779B9
    x = mix(x)

x = mix(x ^ 0xD1B54A33)
```

That final `x` is the **raw hallmark**.

### The important trap

After calculating the raw hallmark, `reseal()` validates the state. A normal
state must satisfy:

```text
length == 16
0 <= ward0 <= 24
0 <= ward1 <= 24
0 <= ward2 <= 24
bite == ward0 + 2*ward1 + 3*ward2
```

If validation fails, the library changes the result:

```python
returned = mix(raw_hallmark ^ 0xA5A5A5A5) ^ 0x0BADF00D
```

The hidden target is intentionally invalid, so calling the exported
`reseal(83, 67, 55, 462)` returns:

```text
0xdc457bf0
```

That is the wrong “spine” mentioned by the game:

```text
PERFECT FACE. WRONG SPINE.
```

To get the real hallmark, we must reproduce the bytecode ourselves and take
the value **before** the invalid-state transformation:

```text
raw hallmark = 0x71d3a101
```

---

## 5. Decrypting the certificate

After the state comparison succeeds, `submit()` uses the supplied hallmark as
the seed for another mixing loop:

```python
for _ in range(1_200_000):
    x = mix(x + 0xC2B2AE35)

x = mix(x ^ 0x85EBCA6B)
```

The library contains this encrypted 28-byte certificate:

```text
2a 53 db 7b a3 5d 34 f5
5f 59 74 5e 00 43 88 1c
a1 13 6f b7 f8 d7 3f 79
c1 b0 af 1a
```

For each encrypted byte, the program mixes the state once more and XORs the
encrypted byte with the highest byte of the result:

```python
x = mix(x + 0xC2B2AE35)
plaintext_byte = encrypted_byte ^ (x >> 24)
```

The verifier checks whether the plaintext starts with `HTB{`. If it does, the
assay returns `ACCEPTED`.

---

## 6. Solver

Here is the complete standalone solver:

```python
#!/usr/bin/env python3
from struct import pack

MASK = 0xFFFFFFFF
C = 0xC2B2AE35
M1 = 0x85EBCA6B
M2 = 0xC2B2AE35

TARGET = (83, 67, 55, 462)

CIPHERTEXT = bytes.fromhex(
    "2a53db7ba35d34f55f59745e0043881c"
    "a1136fb7f8d73f79c1b0af1a"
)


def mix(x):
    x = ((x >> 16) ^ x) * M1 & MASK
    x = ((x >> 13) ^ x) * M2 & MASK
    return ((x >> 16) ^ x) & MASK


def raw_reseal(words):
    x = 0x53437277

    for byte in pack("<4I", *words):
        x ^= byte
        x = ((x << 5) | (x >> 27)) & MASK
        x = (x + 0x9E3779B9) & MASK
        x = mix(x)

    return mix(x ^ 0xD1B54A33)


hallmark = raw_reseal(TARGET)
x = hallmark

for _ in range(1_200_000):
    x = mix((x + C) & MASK)

x = mix(x ^ M1)

certificate = bytearray()

for encrypted_byte in CIPHERTEXT:
    x = mix((x + C) & MASK)
    certificate.append(encrypted_byte ^ (x >> 24))

print("Target:", TARGET)
print(f"Raw hallmark: 0x{hallmark:08x}")
print("Certificate:", certificate.decode())
```

Running it:

```bash
python3 solve.py
```

Output:

```text
Target: (83, 67, 55, 462)
Raw hallmark: 0x71d3a101
Certificate: HTB{p3rf3ct_f4c3_tru3_sp1n3}
```

---

## Flag

```text
HTB{p3rf3ct_f4c3_tru3_sp1n3}
```

The ring's face was the hidden target state, while its “true spine” was the raw
hallmark that the public API tried to hide. Once both pieces were reconstructed,
Vaultrune's assay happily certified the fake.
