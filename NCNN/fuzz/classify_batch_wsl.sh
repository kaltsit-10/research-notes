#!/usr/bin/env bash
# 批量分类 crash_cov/* 按 ASan 类型 → 归档子目录（每类保留 1 个代表性样本）
# 用法: bash classify_batch_wsl.sh   （WSL 内, ncnn_fuzz 目录）
set -uo pipefail
cd /home/kaltsit/vuln_repro/ncnn_fuzz || exit 1
BIN=./fuzz_param_cov
DIR=crash_cov
mkdir -p "$DIR/known_dos" "$DIR/F1_bottom_oob" "$DIR/F2_neg_topcount" "$DIR/other"
declare -A counts
for f in "$DIR"/crash-*; do
  [ -e "$f" ] || continue
  # 已归档的跳过
  case "$f" in
    *known_dos/*|*F1_bottom_oob/*|*F2_neg_topcount/*|*other/*) continue;;
  esac
  out=$(timeout 30 setarch x86_64 -R "$BIN" -runs=1 -rss_limit_mb=4096 "$f" 2>&1)
  if   echo "$out" | grep -q "heap-buffer-overflow"; then cls="F1_bottom_oob"
  elif echo "$out" | grep -q "length_error";            then cls="F2_neg_topcount"
  elif echo "$out" | grep -qE "out-of-memory|allocation-size-too-big|ERROR: libFuzzer: OOM"; then cls="known_dos"
  else cls="other"; fi
  counts[$cls]=$(( ${counts[$cls]:-0} + 1 ))
  # 每类第一个留在原位作为代表样本，其余移入归档
  if [ "${counts[$cls]}" -gt 1 ]; then mv -f "$f" "$DIR/$cls/"; fi
done
echo "分类结果:"
for k in F1_bottom_oob F2_neg_topcount known_dos other; do
  echo "  $k: ${counts[$k]:-0}"
done
