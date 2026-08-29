#!/usr/bin/env bash
# Run the ncnn param fuzz campaign.
#   -close_fd_mask=3 : silence ncnn stderr spam; libFuzzer still keeps crash report fds open
#   -max_len=262144  : match harness cap
#   -max_total_time  : campaign budget (adjust)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CORPUS="$HERE/corpus"

# seed corpus: copy existing local (private) ncnn param files as starting points
if [ ! -d "$CORPUS" ]; then
  mkdir -p "$CORPUS"
  for f in /home/kaltsit/vuln_repro/ncnn/**/*.param; do
    [ -e "$f" ] && cp -f "$f" "$CORPUS/seed_$(basename "$f")" || true
  done
  # plus a minimal well-formed one so the fuzzer starts with a working parse
  printf '7767517\n0 0\n' > "$CORPUS/seed_min.param"
fi

"$HERE/fuzz_param" \
  -dict="$HERE/ncnn_param.dict" \
  -close_fd_mask=3 \
  -max_len=262144 \
  -max_total_time=3600 \
  -print_final_stats=1 \
  "$CORPUS"
