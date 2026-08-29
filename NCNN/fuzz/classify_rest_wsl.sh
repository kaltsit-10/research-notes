#!/usr/bin/env bash
# 对 crash_cov 根目录剩余 crash-* 分类（重跑 fuzzer 归类到子目录）
# 输出每类数量，最后一条汇总。子目录: F1_bottom_oob / F2_neg_topcount /
# F3_ydo_softmax / known_dos / other
set -uo pipefail
cd /home/kaltsit/vuln_repro/ncnn_fuzz || exit 1
BIN=./fuzz_param_cov
DIR=crash_cov
for d in F1_bottom_oob F2_neg_topcount F3_ydo_softmax known_dos other; do
  mkdir -p "$DIR/$d"
done
declare -A counts
for f in "$DIR"/crash-*; do
  [ -e "$f" ] || continue
  out=$(timeout 30 setarch x86_64 -R "$BIN" -runs=1 -rss_limit_mb=4096 "$f" 2>&1)
  if   echo "$out" | grep -q "yolodetectionoutput.cpp"; then cls="F3_ydo_softmax"
  elif echo "$out" | grep -q "heap-buffer-overflow";    then cls="F1_bottom_oob"
  elif echo "$out" | grep -q "length_error";            then cls="F2_neg_topcount"
  elif echo "$out" | grep -qE "paramdict.cpp|out-of-memory|allocation-size-too-big|ERROR: libFuzzer: OOM"; then cls="known_dos"
  else cls="other"; fi
  counts[$cls]=$(( ${counts[$cls]:-0} + 1 ))
  mv -f "$f" "$DIR/$cls/"
done
echo "=== 分类完成 (剩余根目录已清空) ==="
for k in F1_bottom_oob F2_neg_topcount F3_ydo_softmax known_dos other; do
  echo "  $k: ${counts[$k]:-0}"
done
