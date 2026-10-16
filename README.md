# RainFall

A collection of exploit write-ups and working `pwntools` scripts for the École 42 **RainFall** wargame (levels `level00` → `level10`), each defeating a different memory-corruption bug on a remote Linux VM to escalate from `levelN` to `flagN`.

Each level targets a SUID binary owned by the next `flagN` user; a successful exploit spawns a privileged shell and reads `/home/flagN/.pass`, which is both the proof of completion and the password for the next level.

## Techniques covered

| Level | Binary | Vulnerability | Technique |
|-------|--------|----------------|-----------|
| 00 | `case` | `gets()` stack overflow | Shellcode + NOP-sled, stack-address scan (no ASLR, no canary) |
| 01 | `ono` | `read()` stack overflow | ret2win — jump past a dead `0xdeadbeef` check straight into the shell-spawning code |
| 02 | `dixie` | `read()`/`memcpy` stack overflow, executable stack (NX off) | Shellcode staged in `argv[1]` at a fixed stack address, return-pointer pivot |
| 03 | `armitage` | Stack overflow, NX on | ROP: `setreuid` + `system("/bin/sh")`, symbols/gadgets resolved dynamically from libc |
| 04 | `riviera` | Format string (`printf(tag)`) | `printf@GOT` overwritten to `execvp`; exploits a compiled ELF helper named after the format string to preserve SUID |
| 05 | `wintermute` | `gets()` stack overflow, NX on | ROP: `setreuid` + `system("/bin/sh")` with stack alignment gadget |
| 06 | `3jane` | Format string leak + `gets()` overflow, canary present | Leak canary via `%N$p`, reinsert it, then ROP `setreuid` + `system` |
| 07 | `sprawl` | Format string leak + integer-truncation size-check bypass | `uint16_t` truncation of `a*b` lets an oversized `fread()` overflow a canary-protected buffer; canary leaked and replayed, then ROP |
| 08 | `maelcum` | Format string leak + fixed oversized `read()`, limited overflow window | Canary leak, then a stack **pivot** via a double `leave;ret` into a global buffer (`relay_buf`) to fit a full ROP chain |
| 09 | `neuromancer` | Format string leak (+ free libc leak) + `gets()` overflow | Canary leak via `%N$p`, canary-aware ROP `setreuid` + `system` |
| 10 | `tessier` | Format string leak + `gets()` overflow | Canary leak, canary-aware ROP `setreuid` + `system`, bypassing password check and vault secret entirely |

Across levels 06–10, the progression is deliberate: once a stack canary is introduced, every exploit first leaks it through an unrelated `printf(buf)` format-string bug (`%N$p`) before building its overflow payload.

## Mitigations encountered

| Mitigation | Status across levels | How it's defeated |
|---|---|---|
| ASLR | Disabled on early levels, irrelevant (fixed/no-PIE) on later ones | Fixed `[stack]`/libc bases read from `/proc/self/maps` or hardcoded |
| Stack canary | Absent (00–05), present (06–10) | Leaked via a format-string bug elsewhere in the binary, replayed unchanged |
| NX | Off (00, 02), on (03, 05–10) | ROP chains built entirely from libc gadgets/functions instead of injected shellcode |
| SHSTK / IBT (CET) | Enabled on most later levels | Only `pop reg; ret` gadgets and direct `call`-free libc entry points — no indirect branches |
| PIE | Disabled throughout | Binary and gadget addresses hardcoded |
| Partial RELRO | Present on some levels | Exploited directly in level04 (`printf@GOT` overwrite) |

The recurring privilege-handling pattern: `setreuid(uid, uid)` is called **before** `system("/bin/sh")`, because `/bin/sh` (dash) drops a SUID euid when `ruid != euid` — matching the uids first keeps the shell privileged.

## Project Structure

```
.
├── run_all.sh                    # runs every level's run.sh in sequence, prints all flags
├── level00/
│   ├── README.md                 # per-level write-up (vulnerability, exploitation, usage)
│   ├── flag                      # captured flag (password for level01)
│   └── ressource/
│       ├── run.sh                # local driver: SSH, copies + runs the exploit on the VM
│       ├── exploit.py            # pwntools exploit
│       └── exploit.sh            # standalone bash wrapper (run directly on the VM)
├── level01/ … level10/           # same layout per level
```

Level 04 additionally ships a `setup.py` (compiles a helper ELF needed by the exploit), and levels 05–10 ship a `sendtovm.sh` convenience script for manual `scp`.

## Usage

Each level is self-contained. From the local machine (VM listening over SSH on port 4242 by default):

```sh
cd levelNN/ressource
./run.sh                 # copies the exploit to the VM and runs it there
./run.sh <host> <port>   # custom target
```

The SSH password defaults to the previous level's flag (`SSHPASS` env var can override it). Directly on the VM:

```sh
python3 exploit.py       # or: bash exploit.sh, where provided
```

Each script prints the obtained UID and the 32-character flag:

```
uid=1017(flag00) gid=1003(level00) groups=1003(level00),1001(levelgroup)
czugaihitjx0lys47blkh0qwtzz1c9g6
```

### Running every level at once

```sh
./run_all.sh [host [port]]
```

Iterates `level00` → `level10`, running each `run.sh` and printing a summary table of the flag captured at each stage (or `** ECHEC **` on failure).

## Notes

- All exploits target a specific libc build; symbols (`system`, `setreuid`, `execve`, `exit`) and gadgets (`pop rdi; ret`, `pop rsi; ret`) are resolved **dynamically** from the libc on the VM rather than hardcoded, so the scripts stay robust if the VM's libc is updated.
- Several binaries read input greedily (a single `read()`/`gets()` can swallow payload + following lines), which the exploits work around with sacrificial lines or timed resynchronization before driving the resulting shell.
- `level08` is the only level requiring a stack pivot, since its overflow window is too small (16 bytes past the return address) to hold a full ROP chain directly.
