# Secondhand Writeup

## Challenge

**Category:** Reversing  
**File:** `secondhand`  
**Flag:** `HTB{WHY_S00_345Y_H0N}`

## The short version

The binary contains several believable distractions, including an obvious flag-shaped
string. The real path only accepts a very strange eight-byte binary input. It:

1. decrypts a tiny function at runtime;
2. runs our input through that function;
3. jumps into the **middle** of another instruction stream;
4. compares the result with a hidden constant; and
5. decrypts and prints the real flag.

That fits the challenge's hints about a discarded version still being present and
feeding a page from its “inner crease.”

## Initial inspection

First, I checked what kind of file we had:

```bash
$ file secondhand
secondhand: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Running it with no useful input was not very exciting:

```bash
$ ./secondhand
hello
This is a rough cut. What is playing is the version we agreed to air, not the version that happened. The honest take got cut. It is still in here, it is just not the one running.
Facilities, second floor printer. It jams on one page every run, the page in the middle that everyone flips straight past. ...
```

`strings` revealed some unusually direct hints:

```text
This is a rough cut...
The honest take got cut. It is still in here...
the page in the middle that everyone flips straight past
start the page from the inner crease, not from the top
There is a camera in the room...
That is the line we cut into the trailer... It is not in the film.
```

There was also an apparent flag hidden behind one of the visible checks:

```text
HTB{secondhand_rough_cut_v3}
```

However, the program describes that result as something cut into the trailer but
“not in the film.” It is a decoy.

## Main program flow

After cleaning up the decompilation, `main` roughly behaves like this:

```c
length = read_line(input, 256);

if (length == 8) {
    if (hidden_eight_byte_check(input, 8))
        return 0;
}

print_rough_cut_hints();

if (being_debugged()) {
    print_camera_message();
    return 0;
}

if (b_roll(input)) {
    print_trailer_message();
    return 0;
}

if (threat_level_midnight(input, length)) {
    print_trailer_message();
}
```

The important observation is that the unusual eight-byte branch happens **before**
the noisy decoy checks.

The program also checks `/proc/self/status` for `TracerPid` and calls
`ptrace(PTRACE_TRACEME)`. That explains the “camera in the room” message. This is
only anti-debugging; static analysis avoids it completely.

## The first decoy

The exported function `b_roll` expects 28 characters and checks them using a
rolling byte transformation:

```c
expected[i] ==
    ROL8((input[i] + rolling_offset) & 0xff, 3) ^ rolling_key;
```

Undoing that transformation produces:

```text
HTB{secondhand_rough_cut_v3}
```

It certainly looks convincing, but entering it only produces:

```text
That is the line we cut into the trailer. It tested well. It is not in the film.
```

The binary could hardly be clearer: this is not the final flag.

There is also a much larger 16-byte custom-cipher check in
`threat_level_midnight`. It generates a substitution table, round keys, byte
permutations, and rolling rotations. Solving it also reaches the same trailer
message. It is another deliberately expensive distraction.

## The real eight-byte check

For an input of exactly eight bytes, the program packs the bytes into a 64-bit
little-endian integer:

```c
uint64_t value = 0;

for (int i = 0; i < 8; i++)
    value |= (uint64_t)input[i] << (8 * i);
```

It then calls a function at `0x401c50`. That function does not contain the real
calculation directly. Instead, it:

1. allocates writable memory with `mmap`;
2. decrypts 38 bytes from `.rodata`;
3. copies them into the new mapping;
4. changes it to executable memory with `mprotect`;
5. calls it with our 64-bit input; and
6. removes it with `munmap`.

This is a tiny runtime-unpacked function.

### Decrypting the tiny function

The encrypted bytes are read backwards and decoded using:

```python
plain[i] = rol8(encrypted[0x402585 - i], 3) ^ key[i % 7]
```

The seven-byte key at `0x402535` is:

```text
3c 91 e7 2a 5b d0 6f
```

After decrypting and disassembling the 38 bytes, the hidden function is:

```asm
mov rax, rdi
mov r11, 0xa5a5a5a5deadbeef
xor rax, r11
rol rax, 0x11
mov r11, 0x100000001b3
imul rax, r11
not rax
ret
```

In friendlier notation:

```text
result = NOT(
    ROL64(input XOR 0xa5a5a5a5deadbeef, 17)
    × 0x100000001b3
) mod 2^64
```

## Starting from the “inner crease”

The result is passed to another deliberately awkward function at `0x401d90`.
That function calculates a jump offset from the input length:

```text
offset = (length & 31) XOR 14
```

The real branch has a length of eight, so:

```text
(8 & 31) XOR 14 = 6
```

Instead of starting at the normal beginning, execution jumps six bytes into the
code at `0x401dd0`, landing at `0x401dd6`.

This is the literal implementation of the hint about starting from the “inner
crease, not from the top.” x86 instructions have variable lengths, so beginning
in the middle makes the same bytes decode as a different program.

Disassembling from the normal address shows an ordinary hash routine.
Disassembling from `0x401dd6` reveals the hidden check:

```asm
mov r10, 0xb8491337c0debabe
cmp rax, r10
jne fallback
ret
```

Therefore, the runtime-decrypted function must return:

```text
0xb8491337c0debabe
```

## Reversing the calculation

Every operation in the tiny function is reversible:

- `NOT` is undone with another `NOT`;
- multiplication by an odd number modulo `2^64` has an inverse;
- rotate-left is undone by rotate-right; and
- XOR is undone by XOR with the same value.

The modular inverse of `0x100000001b3` modulo `2^64` is:

```text
0xce965057aff6957b
```

So the input integer is:

```text
input = ROR64(
    (NOT target × multiplier_inverse) mod 2^64,
    17
) XOR 0xa5a5a5a5deadbeef
```

This gives:

```text
0x28382f8d1780680f
```

Because the program assembled the input as little-endian, the required bytes are:

```text
0f 68 80 17 8d 2f 38 28
```

Several bytes are not printable, so this cannot be entered normally at a terminal.

## Solver

This script performs the inversion and sends the resulting bytes to the binary:

```python
#!/usr/bin/env python3

import subprocess

MASK = (1 << 64) - 1


def ror64(value, count):
    count %= 64
    return ((value >> count) | (value << (64 - count))) & MASK


target = 0xB8491337C0DEBABE
xor_constant = 0xA5A5A5A5DEADBEEF
multiplier = 0x100000001B3
multiplier_inverse = pow(multiplier, -1, 1 << 64)

value = (~target) & MASK
value = (value * multiplier_inverse) & MASK
value = ror64(value, 17)
value ^= xor_constant

answer = value.to_bytes(8, "little")

print(f"64-bit value: {value:#018x}")
print(f"input bytes:  {answer.hex()}")

result = subprocess.run(
    ["./secondhand"],
    input=answer + b"\n",
    capture_output=True,
)

print(result.stdout.decode())
```

Running it produces:

```text
64-bit value: 0x28382f8d1780680f
input bytes:  0f6880178d2f3828
H4D5_UP_Y0U_M4D3_IT
HTB{WHY_S00_345Y_H0N}
```

The flag text sounds like one last attempt to make us doubt ourselves, but it was
accepted by the platform.

## Flag

```text
HTB{WHY_S00_345Y_H0N}
```

## Takeaway

The challenge is mostly about refusing to trust the first plausible answer.
The visible validators are polished decoys, while the real check is hidden behind
runtime-decrypted code and an overlapping x86 instruction stream. In other words:
when the challenge repeatedly says “not from the top,” try disassembling from the
middle.
