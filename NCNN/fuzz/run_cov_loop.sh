#!/usr/bin/env bash
# ncnn param fuzz 长 campaign 循环（覆盖率引导，脱离会话运行）
# 用法（WSL 内）:
#   setsid nohup bash run_cov_loop.sh </dev/null >/dev/null 2>&1 &
# 循环：fuzz(1h 上限) → 崩溃/OOM/timeout 产物回收 → 每 5 轮 merge 语料库 → 重启
# 关键坑（来自 fuzz-loop-setup）：
#   setarch -R  : WSL2 ASan shadow 初始化失败（PIE 撞 shadow）时禁用 ASLR
#   -rss_limit_mb=4096 : 语料库增长导致的 OOM（默认 2GB 必爆）
#   -runs=-1     : 无限；-runs=0 只是处理语料库
# NOTE: 不用 set -e —— fuzzer 每次崩溃/OOM 都非零退出，set -e 会把整个循环
#      杀死（之前的"多轮 run"全是手动重启伪装出来的）。用 rc=$? 捕获即可。
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/fuzz_param_cov"
DICT="$HERE/ncnn_param.dict"
CORPUS="$HERE/corpus"
LOGDIR="$HERE/campaign_logs"
CRASHDIR="$HERE/crash_cov"
LOG="$LOGDIR/cov_loop.log"
mkdir -p "$LOGDIR" "$CRASHDIR"

# --- seed corpus（首次运行）---
if [ ! -d "$CORPUS" ]; then
  mkdir -p "$CORPUS"
  # globstar 在非交互 bash 不可靠，用 find 递归收集 .param
  find /home/kaltsit/vuln_repro/ncnn -name "*.param" -type f 2>/dev/null | while read -r f; do
    cp -f "$f" "$CORPUS/seed_$(basename "$f")" 2>/dev/null || true
  done
  printf '7767517\n0 0\n' > "$CORPUS/seed_min.param"
  echo "[$(date '+%F %T')] seeded corpus: $(ls "$CORPUS" | wc -l) files" >> "$LOG"
fi

[ -x "$BIN" ] || { echo "[$(date '+%F %T')] FATAL: $BIN missing (run build_cov.sh first)" >> "$LOG"; exit 1; }

# 优先用 setarch 禁用 ASLR（若可用）
LAUNCH=()
if command -v setarch >/dev/null 2>&1 && setarch x86_64 -R true 2>/dev/null; then
  LAUNCH=(setarch x86_64 -R)
fi

run=0
while true; do
  run=$((run+1))
  echo "[$(date '+%F %T')] ===== cov campaign run $run start =====" >> "$LOG"
  # 在 HERE 下运行：libFuzzer crash/timeout/oom 产物落在 CWD
  ( cd "$HERE" && "${LAUNCH[@]}" "$BIN" \
      -dict="$DICT" -close_fd_mask=3 -max_len=262144 \
      -runs=-1 -rss_limit_mb=4096 -detect_leaks=0 -timeout=10 \
      -max_total_time=3600 -print_final_stats=1 \
      "$CORPUS" ) >> "$LOG" 2>&1
  rc=$?
  echo "[$(date '+%F %T')] run $run exit rc=$rc" >> "$LOG"

  # 回收崩溃产物
  n=0
  for c in "$HERE"/crash-* "$HERE"/timeout-* "$HERE"/oom-* "$HERE"/leak-*; do
    if [ -e "$c" ]; then
      mv -f "$c" "$CRASHDIR/" && n=$((n+1))
    fi
  done
  [ "$n" -gt 0 ] && echo "[$(date '+%F %T')] saved $n crash artifacts to crash_cov/" >> "$LOG"

  # 每 5 轮 merge 语料库（限制膨胀，避免 OOM 与扫描变慢）
  if [ $((run % 5)) -eq 0 ]; then
    echo "[$(date '+%F %T')] merging corpus (size before: $(ls "$CORPUS" | wc -l))" >> "$LOG"
    ( cd "$HERE" && "${LAUNCH[@]}" "$BIN" -merge=1 -rss_limit_mb=4096 -close_fd_mask=3 \
        -max_len=262144 "$CORPUS" ) >> "$LOG" 2>&1 || true
    echo "[$(date '+%F %T')] corpus after merge: $(ls "$CORPUS" | wc -l)" >> "$LOG"
  fi

  sleep 3
done
