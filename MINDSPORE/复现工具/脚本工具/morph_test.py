# -*- coding: utf-8 -*-
"""畸形对象二次触发测试：dims=[-5] 静默加载返回的 Parameter，用户访问时的影响。
验证 parameter.py 只查 -1 绕过后的真实危害。"""
import subprocess, hashlib
from mindspore.train.checkpoint_pb2 import Checkpoint

CASES = [
    ("neg5_4", [-5], 4),   # 静默返回畸形对象
    ("neg5_24", [-5], 24),  # 静默（chunk 内）
    ("neg100_4", [-100], 4),
    ("ok_2_8", [2], 8),    # 正常对照
]


def build(fn, dims, cb):
    msg = Checkpoint(); v = msg.value.add(); v.tag = "w"
    v.tensor.tensor_type = "Float32"
    v.tensor.dims.extend(dims)
    v.tensor.tensor_content = b"\x00" * cb
    open(fn, "wb").write(msg.SerializeToString())


ACTIONS = """
import sys
from mindspore import load_checkpoint
fn = sys.argv[1]
d = load_checkpoint(fn)
p = d['w']
print('LOADED shape=', p.shape)
try:
    print('asnumpy=', p.asnumpy())
except BaseException as e:
    print('ASNUMPY-EXC', type(e).__name__, str(e)[:100])
"""

for name, dims, cb in CASES:
    fn = f"/tmp/{name}.ckpt"
    build(fn, dims, cb)
    r = subprocess.run(["/home/kaltsit/ms_env/bin/python", "-c", ACTIONS, fn],
                       capture_output=True, text=True, timeout=60)
    print(f"=== {name} dims={dims} cbytes={cb} rc={r.returncode} ===")
    print(r.stdout.strip())
    if r.returncode != 0:
        print("stderr_tail:", (r.stderr or "").strip().splitlines()[-3:])
