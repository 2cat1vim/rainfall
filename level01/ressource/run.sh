#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run.sh [host [port]]
# Copie le(s) script(s) de ce dossier dans le HOME de l'utilisateur sur la VM
# puis les execute LA-BAS (setup.py avant exploit.py si present). Le mot de
# passe = flag du niveau precedent (surchargeable via la variable SSHPASS).
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
host=${1:-127.0.0.1}
port=${2:-4242}
user=level01

for command in sshpass ssh; do
    command -v "$command" >/dev/null 2>&1 || { printf 'Commande manquante : %s\n' "$command" >&2; exit 1; }
done

: "${SSHPASS:=czugaihitjx0lys47blkh0qwtzz1c9g6}"
export SSHPASS

ssh_opts=(-p "$port" -o StrictHostKeyChecking=accept-new \
          -o PreferredAuthentications=password -o PubkeyAuthentication=no)

# Copie dans le HOME prive (evite le clash /tmp multi-utilisateurs) puis exec
remote_cmd=""
for f in setup.py exploit.py; do
    if [[ -f "$script_dir/$f" ]]; then
        sshpass -e ssh "${ssh_opts[@]}" "$user@$host" "cat > ~/.rf_$f" < "$script_dir/$f"
        remote_cmd+="python3 ~/.rf_$f && "
    fi
done
remote_cmd+="true"

exec sshpass -e ssh "${ssh_opts[@]}" "$user@$host" "cd \$HOME && TERM=xterm $remote_cmd"
