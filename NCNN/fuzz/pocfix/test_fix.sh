#!/usr/bin/env bash
# 修复验证：FIXED vs BASELINE，同一批 PoC
cd /home/kaltsit/vuln_repro/ncnn_fuzz/pocfix

FIXED=/home/kaltsit/vuln_repro/ncnn_fuzz/assess/loadpoc_file_fixed2
VULN=/home/kaltsit/vuln_repro/ncnn_fuzz/assess/loadpoc_file_vuln

echo "=== FIXED build (patched net.cpp) ==="
for f in ncnn_blobidx_oob_149B.parambin ncnn_blobidx_oob_negidx.parambin ncnn_blobidx_oob_p1idx.parambin control_allzero.parambin; do
    echo "--- $f ---"
    "$FIXED" "$f"
    echo "exit=$?"
done

echo
echo "=== BASELINE build (a4d2ea1, unpatched) ==="
for f in ncnn_blobidx_oob_149B.parambin ncnn_blobidx_oob_negidx.parambin ncnn_blobidx_oob_p1idx.parambin control_allzero.parambin; do
    echo "--- $f ---"
    "$VULN" "$f"
    echo "exit=$?"
done
