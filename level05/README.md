# wintermute — exploit writeup

## The bug

`run_query()` reads user input with `gets(query)` into a 96-byte stack
buffer (`QUERY_SIZE`). `gets()` performs no bounds checking, so any
input longer than 96 bytes overflows the buffer and overwrites
adjacent stack data — including the saved return address.

```c
char query[QUERY_SIZE];   // 96 bytes
gets(query);               // unbounded read
```

## Mitigations in play

From the checksec output:

- **No PIE** → the binary's own addresses are fixed, but that doesn't
  matter much here since the payload leans on libc gadgets anyway.
- **No stack canary** → the return address can be overwritten directly
  without needing to guess/leak a canary first.
- **Partial RELRO** → GOT is writable but that's not used by this
  approach.
- **NX enabled** → the stack isn't executable, so classic shellcode-on-
  the-stack won't run. This is why the exploit is built entirely out
  of ROP (return-oriented programming) using gadgets and functions
  already present in libc, rather than injecting shellcode.
- **SHSTK / IBT (CET)** enabled → shadow stack / indirect branch
  tracking. The exploit avoids indirect branches by using plain `ret`-
  based gadgets and direct calls to libc functions, so straight-line
  ROP chains built from `pop; ret` gadgets and `call`-free function
  entry points still work under CET.

## Exploit strategy

Since NX blocks shellcode execution, the exploit builds a **ROP chain**
that calls real libc functions to spawn a shell:

1. **Padding** — `120` bytes of filler (`'A' * 120`) to reach and
   overwrite the saved return address. This offset was determined by
   finding the buffer's distance from the return address on the stack
   (buffer + saved registers/padding).

2. **Stack alignment** — a single extra `ret` gadget is placed first.
   This is a common ROP necessity: `call`-heavy libc functions (which
   use SSE instructions like `movaps`) require the stack to be 16-byte
   aligned when they execute, so one bare `ret` is used to nudge the
   alignment before the real chain runs.

3. **`setreuid(1022, 1022)`** — the target binary is presumably setuid
   to a specific low-privileged/other user; calling `setreuid` with
   matching real and effective UIDs drops/sets the process's privilege
   to that UID before spawning a shell, so the shell inherits the
   correct permissions instead of being immediately dropped by the
   shell itself. This is done with a small gadget chain:
   - `pop rdi; ret` → loads first argument (`1022`, the uid)
   - `pop rsi; ret` → loads second argument (`1022`, the gid)
   - `pop rdx` is reused to zero a register → third argument isn't
     needed by `setreuid`, but the call site expects `rdx` cleared
   - calls `setreuid` directly via its libc address

4. **`execve("/bin//sh", NULL, NULL)`** — after the privilege call
   returns, a second gadget chain sets up arguments for `execve`:
   - `rdi` = address of the `"/bin/sh"` string already present inside
     libc (`addr_shell`, found via `one_gadget`/string search —
     avoids needing to write our own string to memory)
   - `rsi` = `0` (argv = NULL)
   - `rdx` = `0` (envp = NULL)
   - calls `execve` directly via its libc address

5. **`exit()`** — appended as a safety net / clean fallthrough in case
   `execve` ever failed to transfer control, preventing a crash from
   corrupting the interactive session.

## Why this works without an info leak

All the addresses used (`execve`, `setreuid`, `exit`, the `/bin/sh`
string, and the gadgets) are hardcoded as fixed offsets from a known
libc base (`0x7ffff7c00000`). This only works because:

- The target environment has **no ASLR** (or the exploit is run in a
  context — like `process()` with a controlled/empty `env`, or the
  libc base is otherwise known/fixed) so libc's load address is
  predictable.
- The gadget offsets were pre-computed (e.g. with `ROPgadget` or
  `objdump`) against the exact libc version on the target.

In a real ASLR'd remote environment, this script would first need an
information leak (e.g. via a format string or a partial overwrite) to
recover the actual libc base at runtime, then add these same offsets
to it.

## Running it

```sh
python3 exploit.py
```

`pwntools` builds the payload, launches `./wintermute` with an empty
environment (`env={}}`, which also helps keep stack layout/offsets
deterministic), sends the overflow as a single line (consumed by
`gets`), and then drops into an interactive shell once `execve` hands
control to `/bin/sh`.

## Summary

| Stage | Technique |
|---|---|
| Vulnerability | Stack buffer overflow via unbounded `gets()` |
| Bypass for NX | ROP chain instead of shellcode |
| Bypass for no-canary | Direct return-address overwrite, no leak needed |
| Privilege handling | `setreuid()` call before spawning shell |
| Shell spawn | `execve("/bin/sh", NULL, NULL)` using libc's own string |
| Address source | Hardcoded libc base (no ASLR / fixed env) |
