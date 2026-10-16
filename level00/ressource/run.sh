#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run.sh [host [port]]
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
host=${1:-127.0.0.1}
port=${2:-4242}

for command in sshpass ssh; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'Commande manquante : %s\n' "$command" >&2
        exit 1
    fi
done

# Le flag du niveau precedent est le mot de passe de ce niveau.
if [[ -z ${SSHPASS:-} ]]; then
    SSHPASS=level00
fi
export SSHPASS

# On envoie le script local sur le python3 distant via stdin : le chemin local
# n'existe pas sur la VM, donc "python3 <chemin>" echouerait. "python3 -"
# execute le contenu recu ; le binaire cible est pilote par pwntools (pipes
# separees), pas par ce stdin.
if [[ -f "$script_dir/exploit.py" ]]; then
    exec sshpass -e ssh -p "$port" "level00@$host" 'python3 -' < "$script_dir/exploit.py"
else
    exec sshpass -e ssh -p "$port" "level00@$host"
fi
