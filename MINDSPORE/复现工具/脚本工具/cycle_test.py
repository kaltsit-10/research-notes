# -*- coding: utf-8 -*-
"""二次投毒闭环：save_checkpoint 写回的畸形参数能否再次加载并再次保存（传播循环）。"""
import subprocess
from mindspore.train.checkpoint_pb2 import Checkpoint

PY = "/home/kaltsit/ms_env/bin/python"

# 构造 -5 畸形 ckpt
fn = "/tmp/neg5_cycle0.ckpt"
msg = Checkpoint(); v = msg.value.add(); v.tag = "unused"
v.tensor.tensor_type = "Float32"
v.tensor.dims.extend([-5])
v.tensor.tensor_content = b"\x00" * 4
open(fn, "wb").write(msg.SerializeToString())

CYCLE = """
import sys
from mindspore import load_checkpoint, save_checkpoint
src = sys.argv[1]
dst = sys.argv[2]
p = load_checkpoint(src)
k = list(p.keys())[0]
print('LOAD shape=', p[k].shape, 'dtype=', p[k].dtype)
save_checkpoint(p, dst)
print('SAVED ->', dst)
"""

# 循环 3 轮：加载 → 保存 → 加载保存的结果
cur = fn
for i in range(1, 4):
    nxt = f"/tmp/neg5_cycle{i}.ckpt"
    r = subprocess.run([PY, "-c", CYCLE, cur, nxt], capture_output=True, text=True, timeout=60)
    print(f"=== cycle{i} {cur.split('/')[-1]} -> {nxt.split('/')[-1]} rc={r.returncode} ===")
    print(r.stdout.strip())
    if r.returncode != 0:
        print("stderr_tail:", (r.stderr or "").strip().splitlines()[-3:])
        break
    cur = nxt

# 最终产物大小 + 序列化后 dims 是否保留 -5
print("=== final files ===")
import os
for i in range(4):
    f = f"/tmp/neg5_cycle{i}.ckpt"
    if os.path.exists(f):
        m = Checkpoint()
        m.ParseFromString(open(f, "rb").read())
        dims = [x.tensor.dims for x in m.value]
        print(f"{f}: {os.path.getsize(f)}B dims={dims}")
