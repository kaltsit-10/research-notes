#!/usr/bin/env bash
# 覆盖率引导重建：给 libncnn.a 加 trace-pc-guard 插桩，让 libFuzzer 真正看到库内路径。
# 跑这个之后用新二进制做长 campaign 才有意义（现用 build_asan 的库只有 42 个 counter）。
# WSL 内执行。
set -euo pipefail
SRC=/home/kaltsit/vuln_repro/ncnn/ncnn_src
HERE="$(cd "$(dirname "$0")" && pwd)"

# 1) coverage-instrumented libncnn.a
# NOTE: clang-15 libFuzzer 已弃用 trace-pc-guard 与 trace-pc 回调（runtime 直接报错退出）；
#       只接受 inline-8bit-counters + pc-table（边覆盖）(+ trace-cmp 值分析)。
#       验证命令（clang++-15 -fsanitize=fuzzer -###）展开即为
#       -fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp,indirect-calls。
cd "$SRC"
mkdir -p build_fuzz
cd build_fuzz
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fsanitize=address -fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp,indirect-calls" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp,indirect-calls" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
  -DNCNN_BUILD_TOOLS=OFF -DNCNN_BUILD_BENCHMARK=OFF -DNCNN_BUILD_EXAMPLES=OFF \
  .. >/dev/null
make -j"$(nproc)" ncnn

# 2) link harness
cp -f "$HERE/fuzz_param.cc" /home/kaltsit/vuln_repro/ncnn_fuzz/
clang++ -std=c++11 -g -O1 -fsanitize=fuzzer,address -fopenmp=libgomp \
  -I "$SRC/build_fuzz/src" -I "$SRC/src" \
  /home/kaltsit/vuln_repro/ncnn_fuzz/fuzz_param.cc \
  "$SRC/build_fuzz/src/libncnn.a" -lpthread \
  -o /home/kaltsit/vuln_repro/ncnn_fuzz/fuzz_param_cov

echo "[+] built fuzz_param_cov"
/home/kaltsit/vuln_repro/ncnn_fuzz/fuzz_param_cov -runs=0 -print_coverage=1 /dev/null 2>&1 | grep -c "pulse" || true
