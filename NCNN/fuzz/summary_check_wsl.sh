#!/usr/bin/env bash
cd /home/kaltsit/vuln_repro/ncnn_fuzz || exit 1
echo "=== run.log tail ==="
tail -3 run.log 2>/dev/null
echo "=== fuzzer procs ==="
pgrep -f 'fuzz_param_cov' | wc -l
echo "=== run_cov_loop procs ==="
pgrep -f 'run_cov_loop.sh' | wc -l
echo "=== corpus ==="
ls corpus | wc -l
echo "=== crash subdir counts ==="
for d in F1_bottom_oob F2_neg_topcount F3_ydo_softmax known_dos other; do
  printf "%s: %s\n" "$d" "$(ls crash_cov/$d/crash-* 2>/dev/null | wc -l)"
done
echo "root_left: $(ls crash_cov/crash-* 2>/dev/null | wc -l)"
