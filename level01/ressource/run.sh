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
    SSHPASS=czugaihitjx0lys47blkh0qwtzz1c9g6
fi
export SSHPASS

if [[ -f "$script_dir/exploit.py" ]]; then
    exec sshpass -e ssh -p "$port" "level01@$host" python3 "$script_dir/exploit.py"
else
    exec sshpass -e ssh -p "$port" "level01@$host"
fi
