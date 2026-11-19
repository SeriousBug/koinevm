#!/bin/bash
# The refusals a workload meets, ranked.
#
# `tools/sweep.sh` says what the tree holds; this says what running it reaches. Translation is per
# page, so a page's refusals include instructions nothing on the page calls (glibc's SVE string
# routines sit beside the functions that are): the list is an upper bound. What a refusal that is
# reached looks like is a trap at the word, and the run stops there, so a workload that exits 0
# stayed off every one of them.
#
#   bash tools/sweep-run.sh /usr/bin/python3 /tmp/np.py
#   bash tools/sweep-run.sh /bin/bash /tmp/build.sh
#   bash tools/sweep-run.sh --rank target/tmp/gaps-numpy.log
set -uo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--rank" ]; then
    log=$2
    status=0
else
    log=${SWEEP_LOG:-target/tmp/gaps-run.log}
    ARMJIT_LOG_GAPS=1 tools/run-rootfs.sh "$@" 2>"$log"
    status=$?
fi

refusals=$(grep -c '^gap at ' "$log" 2>/dev/null || true)
printf '%s refusals in %s; run exited %s\n' "$refusals" "$log" "$status"
echo
echo "By reason:"
sed -n 's/^gap at [^:]*: //p' "$log" | sort | uniq -c | sort -rn
echo
echo "By word, which is the work:"
sed -n 's/^gap at [^(]*(\([0-9a-f]*\)): \(.*\)/\1 \2/p' "$log" | sort | uniq -c | sort -rn | head -"${TOP:-20}"
echo
echo "By file:"
sed -n 's/^gap at \([^+]*\)+.*/\1/p' "$log" | sort | uniq -c | sort -rn
