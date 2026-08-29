#!/usr/bin/env bash
cd /home/kaltsit/vuln_repro/ncnn_fuzz || exit 1
BIN=./fuzz_param_cov
for f in crash_cov/other/crash-*; do
  [ -e "$f" ] || continue
  echo "=== $(basename "$f") ==="
  xxd "$f" | head -2
  timeout 30 setarch x86_64 -R "$BIN" -runs=1 -rss_limit_mb=4096 "$f" 2>&1 | grep -E "ERROR:|SUMMARY:|Running:|parse " | head -5
  echo
done
