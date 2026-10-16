# level00 — Stack buffer overflow (`gets`)

Objectif : passer de `level00` à `flag00` et récupérer `/home/flag00/.pass`.

## Cible

Binaire `~/case` sur la VM : **SUID `flag00`** (uid 1017), source `case.c` fournie.

```c
static void auth_loop(void) {
    char credentials[64];
    ...
    gets(credentials);          // <-- aucune borne : débordement de pile
    ...
}
```

| Protection | État |
|------------|------|
| ASLR (`/proc/sys/kernel/randomize_va_space`) | **0** (désactivé) |
| Stack canary | absent (SIGSEGV direct) |
| NX | peu importe : on saute dans la pile, ASLR off |

## Faille

`gets()` écrit sans limite dans `credentials[64]`. Le `saved RIP` est à
**88 octets** du début du buffer (mesuré au `cyclic` : `rbp="uaaa"@80`,
`rip="waaa"@88`). On réécrit donc l'adresse de retour pour sauter dans un
shellcode placé sur la pile.

## Exploitation

Shellcode : `setresuid(1017,1017,1017)` (garde l'euid SUID) puis
`execve("/bin/sh")`. Layout du payload :

```
[ 88 o de filler ][ saved RIP = ret ][ NOP-sled 512 o ][ shellcode ]
                        │                    ▲
                        └── pointe quelque part dans le sled ──┘
```

ASLR étant désactivé, la base de pile est la même pour tous les process : on
lit le sommet de `[stack]` dans `/proc/self/maps` (celui du binaire SUID est
illisible), puis on **balaie** `ret` par pas de `0x80` vers le bas. Le grand
NOP-sled rend l'exploit tolérant au décalage d'adresse entre gdb, l'exécution
directe et SSH.

## Utilisation

Depuis la machine locale (la VM doit écouter en SSH, port 4242 par défaut) :

```sh
cd ressource
./run.sh                 # local -> SSH -> lance exploit.py sur la VM
./run.sh <host> <port>   # cible personnalisée
```

Sur la VM directement :

```sh
python3 exploit.py       # ou :  bash exploit.sh
```

Les deux impriment l'UID obtenu et le flag :

```
uid=1017(flag00) gid=1003(level00) groups=1003(level00),1001(levelgroup)
czugaihitjx0lys47blkh0qwtzz1c9g6
```

Ce flag est le mot de passe de `flag00` / `level01`.

## Fichiers

| Fichier | Rôle |
|---------|------|
| `ressource/run.sh` | Driver local : SSH + envoi de `exploit.py` sur la VM |
| `ressource/exploit.py` | Exploit pwntools (auto-détection UID/pile, sled + scan) |
| `ressource/exploit.sh` | Même exploit, wrapper bash autonome (à lancer sur la VM) |
| `e/howto.txt` | Notes de recon (gdb, pwntools, ROP, shellcraft…) |
| `flag` | Flag récupéré |
