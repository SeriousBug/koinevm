#!/bin/bash
# What the translator refuses, over every program and library the root tree holds.
#
# A static sweep is the shape of the work, not the work: a word in an executable segment that no
# path reaches (a literal pool, an SVE routine the loader does not pick because HWCAP advertises no
# SVE) is a refusal that costs nothing. `tools/sweep-run.sh` logs the refusals a workload actually
# reaches; this one says what is there at all.
#
#   bash tools/sweep.sh                  # every ELF under the tree's bin and lib directories
#   ROOTS="bin usr/bin" bash tools/sweep.sh
#   JOBS=8 bash tools/sweep.sh
set -uo pipefail
cd "$(dirname "$0")/.."

armjit=target/release/armjit
root=rootfs/debian
ROOTS=${ROOTS:-"bin sbin usr/bin usr/sbin lib usr/lib"}
JOBS=${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || nproc)}

[ -x "$armjit" ] || { echo "build $armjit first" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p target/tmp

# An ELF is four bytes; the rest of what these directories hold is scripts and links. Symbolic
# links are left out: a link's target is in the tree under its own name, and following one that is
# absolute would leave the tree.
for d in $ROOTS; do
    [ -d "$root/$d" ] || continue
    find "$root/$d" -type f 2>/dev/null
done | sed "s|^$root/||" | while read -r p; do
    [ "$(head -c 4 "$root/$p" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ] && echo "$p"
done | sort -u >"$work/list"
total=$(wc -l <"$work/list" | tr -d ' ')
echo "sweeping $total ELF files with $JOBS jobs" >&2

one() {
    local guest=$1 out err
    err=$(mktemp)
    if ! out=$("$armjit" gaps "$root/$1" --rootfs="$root" --tsv 2>"$err"); then
        printf '%s\t-\t0\t0\t%s\t-\n' "$guest" "$(head -1 "$err")"
        rm -f "$err"
        return 0
    fi
    rm -f "$err"
    [ -n "$out" ] || return 0
    while IFS=$'\t' read -r word n at why decoded where; do
        # The interpreter is one file in every dynamic program, so its gaps are its own: adding
        # them up per program would count the same words a thousand times.
        [ "$where" = "interp+" ] && guest=usr/lib/ld-linux-aarch64.so.1
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$guest" "$word" "$n" "$at" "$why" "$decoded"
    done <<<"$out"
}
export armjit root
export -f one

xargs -P "$JOBS" -I{} bash -c 'one "$@"' _ {} <"$work/list" >"$work/rows"

sort -t$'\t' -k1,1 -k2,2 "$work/rows" >target/tmp/sweep.tsv

# One row per encoding and reason: the refusals, the files that hold it, one example.
awk -F'\t' '
{
  key = $2 "\t" $6 "\t" $5
  n[key] += $3
  files[key]++
  if (!(key in seen)) seen[key] = $1 "+0x" $4
}
END { for (k in n) printf "%d\t%d\t%s\t%s\n", n[k], files[k], k, seen[k] }' "$work/rows" |
    sort -rn >"$work/top"

files=$(cut -f1 "$work/rows" | sort -u | wc -l | tr -d ' ')
refusals=$(awk -F'\t' '{s += $3} END {print s+0}' "$work/rows")
encodings=$(cut -f2 "$work/rows" | sort -u | wc -l | tr -d ' ')

echo "$refusals refusals in $encodings encodings, in $files files of $total; rows in target/tmp/sweep.tsv"
echo
echo "By reason, which is the work:"
awk -F'\t' '
$2 != "-" { n[$5] += $3; seen[$5, $1] = 1 }
END {
  for (k in seen) { split(k, p, SUBSEP); files[p[1]]++ }
  for (r in n) printf "%8d %6d  %s\n", n[r], files[r], r
}' "$work/rows" | sort -rn
failed=$(awk -F'\t' '$2 == "-"' "$work/rows" | wc -l | tr -d ' ')
if [ "$failed" != 0 ]; then
    echo
    echo "Files that did not translate at all:"
    awk -F'\t' '$2 == "-" { print "  " $1 ": " $5 }' "$work/rows"
fi
echo
echo "Top encodings:"
printf '%8s %6s  %-9s %-24s %-38s %s\n' count files word decoded reason example
awk -F'\t' '{ printf "%8d %6d  %-9s %-24.24s %-38.38s %s\n", $1, $2, $3, $4, $5, $6 }' "$work/top" |
    head -"${TOP:-30}"
echo
echo "Files that hold a refusal:"
cut -f1 "$work/rows" | sort | uniq -c | sort -rn | head -20
