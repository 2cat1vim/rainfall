# sprawl — exploit writeup

## Reading the disassembly as pseudo-C

### `route_tag` — format-string leak #2

```c
void route_tag(void) {
    char buf[144];                 // -0x90(%rbp)

    printf("[SPRAWL] Route tag: ");
    fflush(stdout);

    if (fgets(buf, 0x80, stdin) != NULL) {
        printf("[SPRAWL] Routing via ");
        printf(buf);                // <-- user input as the format string
        fflush(stdout);
    }
}
```

Same bug as the previous levels: `printf(buf)` instead of
`printf("%s", buf)`. `fgets` itself is bounded (128 bytes into a
144-byte buffer, so no overflow here), but the unsanitized format
string lets us read arbitrary stack slots with `%N$p`. The exploit
uses `%23$p` to dump the saved canary for the next function's frame:

```python
p.sendlineafter(b'[SPRAWL] Route tag: ', b'%23$p')
p.recvuntil(b'[SPRAWL] Routing via ')
canary = int(p.recvline().strip(), 16)
```

### `read_header`

```c
struct header {
    uint32_t magic;   // +0
    uint16_t a;        // +4
    uint16_t b;        // +6
};

int read_header(struct header *h) {
    printf("[SPRAWL] Header (hex): ");
    fflush(stdout);

    int n = scanf("%x %hx %hx", &h->magic, &h->a, &h->b);
    if (n != 3)             return -1;
    if (h->magic != 0xdeadbeef) return -1;
    return 0;
}
```

Just a format validator — fields `a` and `b` are taken straight from
the input with no range checks of their own.

### `process_packet` — the real bug

```c
void process_packet(void) {
    struct header h;
    char buf[80];                       // -0x50(%rbp), ~72 usable before canary

    if (read_header(&h) < 0) { puts("invalid header"); return; }

    uint16_t total = (uint16_t)(h.a * h.b);   // <-- truncated to 16 bits!
    if (total > 0x40) { puts("packet too large"); return; }

    size_t count = h.a;                 // full 16-bit value, NOT truncated
    printf("[SPRAWL] Transmit (%hu bytes): ", total);
    fflush(stdout);
    getchar();                          // consume one leftover char (newline)

    fread(buf, 1, count, stdin);        // reads `count` bytes, not `total`!

    uint32_t sum = calc_checksum(buf, total);   // checksum only covers `total` bytes
    ...
}
```

This is the actual vulnerability, and it's not a plain `gets()`
overflow like the earlier levels — it's a **size-check /ry integer
truncation bug**:

- The validation multiplies `h.a * h.b` and stores the product in a
  **16-bit** field (`movl ...; mov %ax,-0x6a(%rbp)`), then checks
  *that truncated value* is `<= 0x40`.
- But the number of bytes actually handed to `fread()` is `h.a`
  **alone** (`-0x68(%rbp)`, zero-extended, untruncated) — not the
  product, and not the checked/display value `total`.

So by choosing `h.b = 0`, the product `h.a * 0 = 0` always passes the
`<= 0x40` check — while `h.a` (the real `fread` length) can be set to
anything the 16-bit scanf field allows, far beyond the 80-byte
(really ~72-byte-before-canary) `buf`. This is exactly the header the
exploit sends:

```python
p.sendlineafter(b'[SPRAWL] Header (hex): ', b'deadbeef 0100 0000')
#                                             magic    a=0x100  b=0
```

`a = 0x100` (256) bytes get read by `fread()` into an 80-byte buffer,
while the size check only ever saw `a * b = 0`.

## Mitigations and how each is handled

| Mitigation | Status | How the exploit deals with it |
|---|---|---|
| Stack canary | **Found** | Leaked in `route_tag` via the format-string bug (`%23$p`), then reinserted verbatim at the right offset in the overflow payload. |
| NX | Enabled | ROP chain using libc code only — no shellcode on the stack. |
| PIE | Disabled | Addresses used are hardcoded offsets from a fixed/known libc base rather than leaked at runtime. |
| SHSTK / IBT (CET) | Enabled | Chain built only from `pop reg; ret` gadgets and direct calls to libc function entry points — no indirect branches CET would reject. |
| Partial RELRO | — | Not targeted; GOT isn't touched by this approach. |
| Size check on packet length | **Present, but flawed** | The check truncates `a * b` to 16 bits and validates the wrong quantity; `fread`'s real length (`a`) is never range-checked. |

## Payload layout

```
offset 0  : 72 bytes padding    -> fills buf[80] up to the canary slot
offset 72 : leaked canary (8B)  -> keeps __stack_chk_fail from firing
offset 80 : 8 bytes filler      -> saved rbp
offset 88 : ROP chain starts here, overwriting the saved return address
```

`offset = 72` is the distance from the start of the 80-byte local
`buf` to the canary slot immediately below the saved `rbp`/return
address (`80 - 8`).

### The ROP chain

Same two-stage, libc-only approach as the other levels:

1. **`ret` (stack alignment)** — one bare `ret` gadget first, so the
   stack is 16-byte aligned before the SSE-using libc call sequences
   run.
2. **`setreuid(1024, 1024)`** — `pop_rdi`/`pop_rsi` load the uid/gid
   arguments, then `setreuid`'s libc address is called directly, so
   the eventual shell gets the right privilege level.
3. **`execve("/bin/sh", NULL, NULL)`** — `rdi` points at the
   `"/bin/sh"` string already sitting inside libc (`addr_shell`),
   `rsi`/`rdx` are zeroed via `pop_rsi`/`pop_rdx`, then `execve` is
   called directly.
4. **`exit()`** — appended as a fallback in case `execve` doesn't
   transfer control, so the process terminates cleanly instead of
   running off into garbage.

The whole payload is padded out to 256 bytes (`payload.ljust(256,
b'C')`) to match the `count = 0x100` the crafted header told
`process_packet` to `fread()` — sending fewer bytes would leave
`fread()` blocking, waiting on stdin for the rest.

All addresses (`execve`, `setreuid`, `exit`, `/bin/sh`, gadgets) are
fixed offsets from the known libc base (`0x7ffff7c00000`), which only
works because the environment isn't defeating the exploit with ASLR
for these addresses. Against a real ASLR'd target, the same
format-string primitive in `route_tag` could be extended to leak a
libc pointer instead of just the canary.

## Running it

```sh
python3 exploit.py
```

The script: leaks the canary through the `route_tag` format-string
bug, sends a crafted header (`magic` valid, `a=0x100`, `b=0`) to
smuggle a 256-byte read past the 16-bit-truncated size check, then
sends the padding + canary + ROP chain as the packet body consumed by
`fread()` in `process_packet`. Once `execve` runs, it drops into an
interactive shell.

## Summary

| Stage | Technique |
|---|---|
| Vulnerability 1 | Format-string bug in `route_tag` (`printf(buf)` instead of `printf("%s", buf)`) |
| Vulnerability 2 | Size-check truncation in `process_packet`: validates `(a*b) & 0xffff` but `fread()`s the untruncated `a`, overflowing the 80-byte stack buffer |
| Canary bypass | Leak canary with `%23$p`, reinsert it unchanged in the overflow payload |
| NX bypass | ROP chain instead of shellcode |
| Privilege handling | `setreuid()` call before spawning shell |
| Shell spawn | `execve("/bin/sh", NULL, NULL)` using libc's own string |
| Address source | Hardcoded libc base (no ASLR / fixed env) |
