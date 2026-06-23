#!/usr/bin/env sh
# Smoke test for the shell port. POSIX sh; asserts real offline lookups.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SH="$HERE/dvmobile.sh"
fail=0
check() { if [ "$1" = "$2" ]; then echo "ok   - $3"; else echo "FAIL - $3 (got [$1] want [$2])"; fail=1; fi; }
contains() { if printf '%s' "$1" | grep -q "$2"; then echo "ok   - $3"; else echo "FAIL - $3"; fail=1; fi; }

out="$(sh "$SH" challenges)"
contains "$out" "idor-profile" "challenges lists idor-profile"
contains "$out" "jwt-none" "challenges lists jwt-none"

n="$(sh "$SH" challenges | wc -l | tr -d ' ')"
check "$n" "4" "challenges prints four rows"

out="$(sh "$SH" cve CVE-2021-44228)"
contains "$out" "Log4j" "log4j CVE resolves offline"

rc=0; sh "$SH" cve CVE-0000-00000 >/dev/null 2>&1 || rc=$?
check "$rc" "1" "unknown CVE exits 1"

cnt="$(sh "$SH" count)"
if [ "$cnt" -ge 100000 ]; then echo "ok   - bundled DB has 100k+ records ($cnt)"; else echo "FAIL - DB count $cnt"; fail=1; fi

[ "$fail" -eq 0 ] && echo "ALL SHELL TESTS PASSED" || { echo "SHELL TESTS FAILED"; exit 1; }
