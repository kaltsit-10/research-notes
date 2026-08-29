# -*- coding: utf-8 -*-
"""汇总 /tmp/ms_*.tsv 全部 dtype 矩阵，输出按 dtype 的 dims×cbytes 网格 + 跨 dtype 差异。"""
import glob
from collections import defaultdict

agg = defaultdict(dict)
for f in glob.glob("/tmp/ms_*.tsv"):
    for line in open(f):
        line = line.strip()
        if not line:
            continue
        v, dims, cb, dt = line.split("\t")
        agg[(dt, dims)][int(cb)] = v

DTYPES = ["Float32", "Float16", "Int4", "Int8", "UInt8", "Bool"]
DIMS = ["(empty)", "0", "1", "2", "3", "10", "-1", "-5", "-100",
        "-2147483647", "-2147483648", "2147483648", "-2147483649", "99999999999"]
LENS = [4, 8, 16, 24, 32, 64, 256]
SHORT = {"CRASH": "C", "EXC": "E", "OK": "O"}

for dt in DTYPES:
    print(f"\n===== {dt} =====")
    print("dims\t" + "\t".join(str(l) for l in LENS))
    for d in DIMS:
        if (dt, d) in agg:
            cells = [agg[(dt, d)].get(l, "?") for l in LENS]
            print(f"{d}\t" + "\t".join(cells))

# 跨 dtype 一致性：同一个 (dims, cbytes) 在不同 dtype 的 verdict 是否有分歧
print("\n===== 跨 dtype 分歧 (同一 dims+cbytes 不同 dtype 结果不同) =====")
all_dims = sorted({d for (_, d) in agg})
conflicts = 0
for d in all_dims:
    for l in LENS:
        vs = {dt: agg[(dt, d)].get(l) for dt in DTYPES if (dt, d) in agg}
        uniq = set(v for v in vs.values() if v is not None)
        if len(uniq) > 1:
            conflicts += 1
            print(f"  dims={d} cbytes={l}: " + " ".join(f"{dt}={v}" for dt, v in vs.items()))
print(f"total conflicts: {conflicts}")

# 每种 dims 的崩溃最小 cbytes（跨 dtype）
print("\n===== 每 dims 首个 CRASH 的 cbytes（各 dtype） =====")
for d in all_dims:
    row = []
    for dt in DTYPES:
        crashes = [l for l in LENS if agg[(dt, d)].get(l) == "CRASH"]
        row.append(f"{dt}:{crashes[0] if crashes else '-'}")
    print(f"  dims={d}: " + " ".join(row))
