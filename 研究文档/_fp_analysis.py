#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""误报分析：扫描 MNN core + TNN interpreter，量化各模式的真实命中/疑似误报分布"""
import json
import subprocess
import sys
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8")

BASE = r"C:\Users\asus\Desktop\study\科研相关\具身智能ai漏洞测试"
DETECT = BASE + r"\.dsh\skills\cwe-repair\scripts\cwe_detect.py"
TARGETS = {
    "MNN_core": BASE + r"\TOOLTEST_MNN\src\source\core",
    "TNN_interp": BASE + r"\TOOLTEST_TNN\src\source\tnn\interpreter",
}

for label, target in TARGETS.items():
    r = subprocess.run(
        [sys.executable, "-X", "utf8", DETECT, target, "--cwe", "125,787,190,369,476,248",
         "--json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        d = json.loads(r.stdout)
    except Exception as e:
        print(f"{label}: JSON 解析失败 {e}")
        continue
    findings = d["findings"]
    by_pat = Counter(f["pattern"] for f in findings)
    print(f"===== {label}: {d['files_scanned']} 文件, {len(findings)} 命中 =====")
    for pat, cnt in by_pat.most_common():
        print(f"  {pat}: {cnt}")
    print()
