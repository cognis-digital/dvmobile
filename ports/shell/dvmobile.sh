#!/usr/bin/env sh
# dvmobile (POSIX shell port) — lists the MASVS challenges and resolves
# CVE/GHSA identifiers against the bundled offline OSV DB
# (cognis_vulndb.jsonl.gz). Offline only: gzip -dc + grep, no network.
#
#   ./dvmobile.sh challenges [--cves]
#   ./dvmobile.sh cve CVE-2021-44228
#   ./dvmobile.sh count
#
# Dependencies: sh, gzip, grep, sed (all standard). No jq required.
set -eu

# Resolve the repo root by walking up to find the bundled DB.
find_up() {
  rel="$1"
  dir="$(pwd)"
  i=0
  while [ "$i" -lt 6 ]; do
    if [ -e "$dir/$rel" ]; then printf '%s\n' "$dir/$rel"; return 0; fi
    parent="$(dirname "$dir")"
    [ "$parent" = "$dir" ] && break
    dir="$parent"
    i=$((i + 1))
  done
  printf '%s\n' "$rel"
}

DB="$(find_up dvmobile/cognis_vulndb.jsonl.gz)"
CATALOG="$(find_up ports/challenges.json)"

cmd_challenges() {
  show_cves=0
  [ "${1:-}" = "--cves" ] && show_cves=1
  # Pull id/masvs/title/cwe/real_world_cves out of the JSON with sed (one
  # challenge object per match). Keeps the port jq-free.
  ids=$(grep -o '"id": "[^"]*"' "$CATALOG" | sed 's/"id": "//;s/"//')
  i=1
  for id in $ids; do
    masvs=$(grep -o '"masvs": "[^"]*"' "$CATALOG" | sed -n "${i}p" | sed 's/"masvs": "//;s/"//')
    diff=$(grep -o '"difficulty": "[^"]*"' "$CATALOG" | sed -n "${i}p" | sed 's/"difficulty": "//;s/"//')
    title=$(grep -o '"title": "[^"]*"' "$CATALOG" | sed -n "${i}p" | sed 's/"title": "//;s/"//')
    cwe=$(grep -o '"cwe": "[^"]*"' "$CATALOG" | sed -n "${i}p" | sed 's/"cwe": "//;s/"//')
    printf '%-16s [%-6s] %-14s %s\n' "$id" "$diff" "$masvs" "$title"
    [ "$show_cves" -eq 1 ] && printf '                 %s\n' "$cwe"
    i=$((i + 1))
  done
}

cmd_cve() {
  want="$1"
  if [ -z "$want" ]; then echo "usage: dvmobile.sh cve <id>" >&2; return 2; fi
  # Match JSONL records whose id or aliases contain the (whole-word) identifier.
  hits=$(gzip -dc "$DB" | grep -F "\"$want\"" || true)
  if [ -z "$hits" ]; then
    echo "no match for $want in the bundled offline DB"
    return 1
  fi
  printf '%s\n' "$hits" | while IFS= read -r line; do
    id=$(printf '%s' "$line" | grep -o '"id":"[^"]*"' | head -n1 | sed 's/"id":"//;s/"$//')
    eco=$(printf '%s' "$line" | grep -o '"ecosystem":"[^"]*"' | head -n1 | sed 's/"ecosystem":"//;s/"$//')
    sum=$(printf '%s' "$line" | grep -o '"summary":"[^"]*"' | head -n1 | sed 's/"summary":"//;s/"$//')
    printf '%s  [%s]\n  %s\n' "$id" "$eco" "$sum"
  done
}

cmd_count() {
  gzip -dc "$DB" | grep -c '"id"'
}

case "${1:-}" in
  challenges) shift; cmd_challenges "${1:-}" ;;
  cve)        shift; cmd_cve "${1:-}" ;;
  count)      cmd_count ;;
  *) echo "usage: dvmobile.sh (challenges [--cves] | cve <id> | count)"; exit 1 ;;
esac
