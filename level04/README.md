# level04 — Format string → `printf@GOT` = `execvp`

Objectif : passer de `level04` à `flag04` et récupérer `/home/flag04/.pass`.

## Cible

Binaire `~/riviera` sur la VM : **SUID `flag04`** (uid 1021), non-PIE. Il lit
un **Tag** puis un **Message**, les stocke dans un journal, et réaffiche la
dernière entrée via `display_entry`.

```c
void display_entry(int i){
    printf("[RIVIERA] [%u] tag=", entry[i].seq);
    printf(entry[i].tag);                 // <-- FORMAT STRING (tag controle)
    printf("  msg=%s\n", entry[i].msg);   // msg affiche en %s (sans danger)
}
// handle_input : fgets(tag,0x20,..) puis strncpy(.,tag,0x1f) -> Tag <= 31 o
// main : handle_input(); flush_log();  flush_log rappelle display_entry
```

| Protection | État |
|------------|------|
| PIE | **non** (base `0x400000`, GOT à adresse fixe) |
| RELRO | **partiel** → GOT inscriptible |
| NX | activé |
| SHSTK / IBT (CET) | **activés** → forward-edge only (pas de ROP/ret) |
| ASLR | **0** → base libc fixe `0x7ffff7c00000` |

## Faille

`printf(entry[i].tag)` est appelé **sans format** sur une donnée contrôlée :
écriture arbitraire via `%n`. Contraintes :

- **Tag ≤ 31 octets** (`strncpy ..,0x1f`).
- SHSTK interdit le ROP → on ne peut que faire du **forward-edge** : écraser
  une entrée GOT par une fonction libc (qui commence par `endbr64`, donc
  IBT-compatible).
- Les **adresses cibles** vont dans le Message (sur la pile de `handle_input`,
  atteint par les arguments positionnels `$10`, `$11`… — pas par le Tag qui
  reste court).

## Exploitation

`printf@GOT` (0x404010) pointe déjà sur la libc (octets hauts `f7 ff 7f`
corrects, ASLR off). On ne réécrit que les **3 octets bas** → `execvp`. Ensuite
`flush_log` rappelle `display_entry` → `printf(tag)` devient **`execvp(tag,0)`**.

Le **Tag est aussi le nom d'un binaire** (voir `setup.py`) placé dans
`PATH=/home/level04`. `execvp` le trouve et l'exécute. Comme c'est un **ELF
compilé** (pas un script), `execve` **préserve l'euid flag04** → ce binaire lit
le flag. (`system()`/`dash` abandonnerait l'euid : inutilisable ici.)

```
printf@GOT = &execvp          (via la format string, writes tout-positionnels)
        │
        ▼  flush_log -> display_entry -> printf(tag)
execvp("%1$..c%10$hhn%1$..c%11$hn", NULL)   -> PATH=/home/level04
        │
        ▼
./%1$..  = ELF compilé (euid flag04 conservé)  ->  lit /home/flag04/.pass
```

### Quatre pièges résolus

1. **Tag ≤ 31 o** → format string tout-positionnelle (29 o).
2. **Décompte `%n`** : les littéraux imprimés (ex. un préfixe) comptent dans la
   largeur — ici pas de préfixe, mais la largeur du 2ᵉ write tient compte du 1ᵉ.
3. **`fgets`/newline** : un Tag < 31 o doit être suivi d'un newline séparateur
   (sinon `fgets(32)` déborde sur le Message et désaligne `$10/$11`).
4. **Buffering stdio** : sans importance ici car on n'alimente pas de shell —
   le binaire nommé fait tout.

### Pourquoi `execvp` et pas `system`

`system("sh;…")` donne bien l'exécution de code, **mais** `/bin/sh` = dash
abandonne le SUID (`ruid=euid=level04`) → flag illisible. `execve` d'un ELF
conserve l'euid flag04 : d'où le binaire-dont-le-nom-est-la-format-string.

## Utilisation

Depuis la machine locale (VM en écoute SSH, port 4242 par défaut) :

```sh
cd ressource
./run.sh                 # copie setup.py + exploit.py dans ~, lance setup PUIS exploit
./run.sh <host> <port>   # cible personnalisée
```

Sur la VM directement :

```sh
python3 setup.py         # compile le binaire helper (nom = format string)
python3 exploit.py       # déclenche l'exploit
```

Sortie :

```
[+] flag04 = x0w8xdgapz3tjopq2s11a27yro7krazm
```

Ce flag est le mot de passe de `flag04` / `level05`.

## Fichiers

| Fichier | Rôle |
|---------|------|
| `ressource/run.sh` | Driver local : SSH, copie `setup.py`+`exploit.py` dans `~`, lance les deux |
| `ressource/setup.py` | Compile l'ELF helper `/home/level04/<format-string>` qui lit le flag |
| `ressource/exploit.py` | Format string → `printf@GOT`=`execvp` → exécute le helper |
