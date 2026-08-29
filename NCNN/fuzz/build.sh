#!/usr/bin/env bash
# Build ncnn param fuzz target with clang 14 libFuzzer + ASan.
# Links against the existing ASan-instrumented libncnn.a in build_asan.
#
# Run from WSL, e.g.:  bash /mnt/c/Users/asus/Desktop/study/科研相关/具身智能ai漏洞测试/复现实验/ncnn_fuzz/build.sh
set -euo pipefail

SRC=/home/kaltsit/vuln_repro/ncnn/ncnn_src
BUILD="$SRC/build_asan"
HERE="$(cd "$(dirname "$0")" && pwd)"

CLANG=/usr/bin/clang++
if [ ! -x "$CLANG" ]; then CLANG=clang++; fi
echo "[*] compiler: $CLANG"
"$CLANG" --version | head -1

INC_ORDER="-I $BUILD/src -I $SRC/src"    # generated platform.h must shadow src platform.h.in

echo "[*] building fuzz_param..."
"$CLANG" \
  -std=c++11 \
  -g -O1 \
  -fsanitize=fuzzer,address -fno-omit-frame-pointer \
  -fopenmp=libgomp \
  $INC_ORDER \
  "$HERE/fuzz_param.cc" \
  "$BUILD/src/libncnn.a" \
  -lpthread \
  -o "$HERE/fuzz_param"

echo "[*] done: $HERE/fuzz_param"
"$HERE/fuzz_param" -help=1 2>&1 | head -3 || true
