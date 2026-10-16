# 3jane — exploit writeup

## Reading the disassembly as pseudo-C

The binary is stripped of its stack-canary conversation but not of
symbols, so we can walk the functions in order and translate them.

### `init_vault`

```c
struct entry { int32_t id; int32_t clearance; char label[16]; };
struct entry vault[4];            // at 0x4040c0
int32_t clearances[4];            // at 0x402130
char *labels[4];                  // at 0x404080

void init_vault(void) {
    for (int i = 0; i <= 3; i++) {
        vault[i].id        = i;
        vault[i].clearance = clearances[i];
        strncpy(vault[i].label, labels[i], 15);
        snprintf(vault[i].label, 0x20, "%s", ...);   // formats label in place
    }
}
```

Nothing exploitable here — just seeding data.

### `log_request` — the format-string bug

```c
void log_request(void) {
    char buf[64];                 // -0x50(%rbp)

    printf("Request ID: ");
    fflush(stdout);
    fgets(buf, 0x40, stdin);
    buf[strcspn(buf, "\n")] = 0;  // strip trailing newline

    printf("Logging: ");
    printf(buf);                  // <-- user input passed AS the format string
    putchar('\n');

    access_log_idx++;
}
```

The call at `0x401498` is `printf(buf)` — **not** `printf("%s", buf)`.
Whatever the user types is interpreted as a *format string*. That
means `%p`, `%x`, `%n`, and positional specifiers like `%15$p` are all
live. This is a classic format-string vulnerability, and it's what
the exploit uses to leak the **stack canary** before ever touching
the overflow in `authenticate`:

```python
p.sendline(b'%15$p')
```

`%15$p` asks `printf` to print the 15th argument on the stack (in
`printf`'s own calling convention) as a pointer — and at that stack
offset, for this build, that slot happens to hold the saved canary
value for `authenticate`'s frame (stack layouts are consistent
between calls since there's no ASLR in play for the addresses used
and the program takes the same code path each run). The script reads
that value back out of the `"Logging: "` line and parses it as an
integer:

```python
p.recvuntil(b'Logging: ')
data = p.recvuntil(b'Access code: ')
canary = int(data.split(b'\n')[0], 16)
```

### `authenticate` — the overflow, now canary-aware

```c
void authenticate(void) {
    char buf[144];                // -0x90(%rbp)

    printf("Access code: ");
    fflush(stdout);
    gets(buf);                    // unbounded read — the overflow

    if (strncmp(buf, "<password>", 11) == 0)
        printf("Access granted, clearance level %u\n", vault[1].clearance);
    else
        puts("Access denied.");
}
```

`gets()` again has no bounds checking. Unlike `wintermute`, this
binary has **`Stack: Canary found`** — `checksec` confirms a canary
check is compiled into the prologue/epilogue (the `fs:0x28` /
`__stack_chk_fail` pattern repeats in every function, including this
one). A naive overflow that blindly smashes the return address would
corrupt the canary and get caught at the `leave; ret`, calling
`__stack_chk_fail` instead of returning.

This is exactly why the format-string leak in `log_request` comes
first: it recovers the canary's actual runtime value, so the overflow
payload can **put the correct canary back in place** at the right
stack offset, leaving the check satisfied.

## Mitigations and how each is handled

| Mitigation | Status | How the exploit deals with it |
|---|---|---|
| Stack canary | **Found** | Leaked via the `log_request` format-string bug (`%15$p`), then replayed at the correct offset in the overflow payload so the canary check passes. |
| NX | Enabled | No shellcode on the stack — the payload is a ROP chain using only libc code (`execve`, `setreuid`, gadgets). |
| PIE | Disabled | Not directly relevant to this payload; libc base is assumed fixed/known rather than leaked. |
| SHSTK / IBT (CET) | Enabled | The chain is built from plain `pop reg; ret` gadgets and direct calls to libc function entry points — no indirect jumps that CET would flag. |
| Partial RELRO | — | Not targeted; the GOT isn't overwritten by this approach. |

## Payload layout

```
offset 0   : 136 bytes padding   -> fills buf[144] up to the canary slot
offset 136 : leaked canary (8B)  -> keeps __stack_chk_fail from firing
offset 144 : 8 bytes filler      -> saved rbp
offset 152 : ROP chain starts here, overwriting the saved return address
```

The **136-byte offset** is `144 - 8`: the 144-byte local buffer minus
the 8 bytes the canary occupies immediately below the saved `rbp`/
return address — i.e. padding reaches right up to, but not past, the
canary before it's reinserted verbatim.

### The ROP chain itself

Same two-stage approach as the `wintermute` exploit:

1. **`ret` (stack alignment)** — a single bare `ret` gadget first, to
   get the stack 16-byte aligned before calling into libc functions
   that use SSE instructions internally.

2. **`setreuid(1023, 1023)`** — sets real and effective uid/gid to a
   matching value via `pop rdi; pop rsi; pop rdx` gadgets feeding
   arguments, then a direct call to `setreuid`'s libc address. This
   ensures the spawned shell has the right privilege level rather
   than being dropped.

3. **`execve("/bin/sh", NULL, NULL)`** — `rdi` is loaded with the
   address of a `"/bin/sh"` string already present inside libc
   (`addr_shell`), `rsi`/`rdx` are zeroed (`argv`/`envp` = NULL), then
   `execve`'s libc address is called directly.

4. **`exit()`** — appended as a fallback so that if `execve` somehow
   fails to transfer control, the process exits cleanly instead of
   continuing to execute garbage and crashing the session.

All addresses (`execve`, `setreuid`, `exit`, `/bin/sh`, and the
gadgets) are hardcoded as fixed offsets from a known libc base
(`0x7ffff7c00000`), which only works because ASLR isn't defeating the
exploit in this environment (fixed/controlled base). In a real ASLR'd
target, the format-string bug used here for the canary leak could
just as easily be extended (e.g. `%N$p` against a different stack
slot, or a `GOT`/`.data` pointer dump) to leak a libc address too.

## Running it

```sh
python3 exploit.py
```

The script: connects to `./3jane`, triggers the format-string leak to
recover the canary, builds the padding + canary + ROP payload, sends
it to `authenticate`'s `gets()`, and drops into an interactive shell
once `execve` hands off control.

## Summary

| Stage | Technique |
|---|---|
| Vulnerability 1 | Format-string bug in `log_request` (`printf(buf)` instead of `printf("%s", buf)`) |
| Vulnerability 2 | Stack buffer overflow via unbounded `gets()` in `authenticate` |
| Canary bypass | Leak canary with `%15$p`, reinsert it unchanged in the overflow payload |
| NX bypass | ROP chain instead of shellcode |
| Privilege handling | `setreuid()` call before spawning shell |
| Shell spawn | `execve("/bin/sh", NULL, NULL)` using libc's own string |
| Address source | Hardcoded libc base (no ASLR / fixed env) |
