#!/usr/bin/env bash
# Lance tous les exploits RainFall (level00 -> level10) via leur run.sh
# et affiche le flag obtenu pour chaque niveau.
# Usage: ./run_all.sh [host [port]]
set -uo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

host=${1:-127.0.0.1}
port=${2:-4242}

printf '====== RainFall — tous les flags (level00 -> level10) ======\n'
printf 'cible : %s:%s\n\n' "$host" "$port"
printf '%-9s  %s\n' "niveau" "flag"
printf '%-9s  %s\n' "---------" "--------------------------------"

for n in 00 01 02 03 04 05 06 07 08 09 10; do
    run="./level$n/ressource/run.sh"
    if [[ ! -x "$run" ]]; then
        printf '%-9s  %s\n' "level$n" "(pas de run.sh)"
        continue
    fi
    out=$(timeout 90 "$run" "$host" "$port" 2>/dev/null || true)
    flag=$(printf '%s\n' "$out" | grep -oE '[a-z0-9]{32}' | tail -1)
    printf '%-9s  %s\n' "level$n" "${flag:-** ECHEC **}"
done

printf '\n============================================================\n'
