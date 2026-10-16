# level02 — Stack overflow → shellcode en `argv` (pile exécutable)

Objectif : passer de `level02` à `flag02` et récupérer `/home/flag02/.pass`.

## Cible

Binaire `~/dixie` sur la VM : **SUID `flag02`** (uid 1019), non-PIE. Il lit une
entrée via `read()` puis la recopie (`memcpy`).

| Protection | État |
|------------|------|
| PIE | **non** (base `0x400000`) |
| Stack canary | absent |
| NX | **absent** → pile **exécutable** (segments RWX) |
| SHSTK / IBT (CET) | activés (sans gêne : on saute sur la pile, pas un `ret`) |
| ASLR | **0** → adresses de pile fixes (argv/env reproductibles) |

## Faille

`read()` déborde le buffer sans canary. La pile étant **exécutable** et l'ASLR
désactivé, l'astuce consiste à placer le **shellcode dans `argv[1]`** : il se
retrouve à une **adresse de pile fixe** (`ADDR`, mesurée sous gdb). On réécrit
ensuite le pointeur de retour pour sauter dessus.

Le payload (stdin) sature la zone écrasée de l'adresse du shellcode, puis un
**octet de pivot** `0x78` finit de rediriger l'exécution :

```
argv[1] = shellcode            ← à ADDR (pile fixe, exécutable)
stdin   = [ ADDR × 8 ][ 0x78 ] ← réécrit le pointeur sauvé -> saute sur ADDR
```

## Exploitation

Shellcode (sans octet nul) :

```asm
execve("/bin//sh", ["/bin//sh", "-p"], NULL)
```

Détail clé : l'argument **`-p`**. `/bin/sh` = dash **abandonne l'euid SUID** si
`ruid ≠ euid` — sauf si on le lance avec `-p`, qui **conserve** les privilèges.
Le shell obtenu tourne donc en **euid `flag02`** et peut lire le flag (aucun
`setreuid` nécessaire, contrairement au level03).

## Utilisation

Depuis la machine locale (VM en écoute SSH, port 4242 par défaut) :

```sh
cd ressource
./run.sh                 # copie exploit.py dans ~ sur la VM et l'exécute LÀ-BAS
./run.sh <host> <port>   # cible personnalisée
```

Sur la VM directement :

```sh
python3 exploit.py
```

Sortie :

```
[+] flag02 = qeplvibynup98phqb312dkvhtpdkklac
```

Ce flag est le mot de passe de `flag02` / `level03`.

## Fichiers

| Fichier | Rôle |
|---------|------|
| `ressource/run.sh` | Driver local : SSH, copie `exploit.py` dans `~` sur la VM puis l'exécute |
| `ressource/exploit.py` | Exploit pwntools (shellcode `execve /bin//sh -p` en argv + pivot) |
