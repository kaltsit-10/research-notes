# -*- coding: utf-8 -*-
"""构造 -5 畸形 ckpt 并逐个场景独立 subprocess 跑（崩溃隔离）。"""
import subprocess
from mindspore.train.checkpoint_pb2 import Checkpoint

PY = "/home/kaltsit/ms_env/bin/python"
EXP = "/tmp/exp_neg5.py"


def build(fn, tag, dims, cb, dtype="Float32"):
    msg = Checkpoint(); v = msg.value.add(); v.tag = tag
    v.tensor.tensor_type = dtype
    v.tensor.dims.extend(dims)
    v.tensor.tensor_content = b"\x00" * cb
    open(fn, "wb").write(msg.SerializeToString())


CASES = [
    # (场景, 文件名, tag, dims, content)
    ("into_net",   "/tmp/neg5_fcweight.ckpt", "fc.weight", [-5], 4),
    ("skip_infer", "/tmp/neg5_unused.ckpt",   "unused",     [-5], 4),
    ("skip_train", "/tmp/neg5_unused.ckpt",   "unused",     [-5], 4),
    ("save",       "/tmp/neg5_unused.ckpt",   "unused",     [-5], 4),
    ("delayed",    "/tmp/neg5_unused.ckpt",   "unused",     [-5], 4),
    ("load_only",  "/tmp/neg5_unused.ckpt",   "unused",     [-5], 4),
    # content=28B 物理越界 4B（静默污染 prev_size）后的使用
    ("skip_infer", "/tmp/neg5_unused28.ckpt", "unused",     [-5], 28),
    ("load_only",  "/tmp/neg5_unused28.ckpt", "unused",     [-5], 28),
    # 对照：正常 ckpt 全流程
    ("skip_infer", "/tmp/ok_unused.ckpt",     "unused",     [2], 8),
    ("load_only",  "/tmp/ok_unused.ckpt",     "unused",     [2], 8),
]

done = set()
for scene, fn, tag, dims, cb in CASES:
    build(fn, tag, dims, cb)
    if (scene, fn) in done:
        continue
    done.add((scene, fn))
    r = subprocess.run([PY, EXP, scene, fn], capture_output=True, text=True, timeout=90)
    tail = (r.stderr or "").strip().splitlines()[-3:]
    print(f"=== {scene} {fn.split('/')[-1]} (dims={dims} cb={cb}) rc={r.returncode} ===")
    print(r.stdout.strip())
    if r.returncode != 0:
        print("stderr_tail:", tail)
