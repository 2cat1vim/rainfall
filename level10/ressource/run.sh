#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run.sh [host [port]]
# Copie exploit.py dans le HOME de l'utilisateur sur la VM puis l'exécute
# LÀ-BAS. Le mot de passe = flag du niveau précédent (surchargeable via SSHPASS).
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
host=${1:-127.0.0.1}
port=${2:-4242}
user=level10

for command in sshpass ssh; do
    command -v "$command" >/dev/null 2>&1 || { printf 'Commande manquante : %s\n' "$command" >&2; exit 1; }
done

: "${SSHPASS:=kl9th7ox72218n3jlf554eymtlaynogo}"
export SSHPASS

ssh_opts=(-p "$port" -o StrictHostKeyChecking=accept-new \
          -o PreferredAuthentications=password -o PubkeyAuthentication=no)

sshpass -e ssh "${ssh_opts[@]}" "$user@$host" "cat > ~/.rf_exploit.py" < "$script_dir/exploit.py"
exec sshpass -e ssh "${ssh_opts[@]}" "$user@$host" "cd \$HOME && TERM=xterm python3 ~/.rf_exploit.py"
