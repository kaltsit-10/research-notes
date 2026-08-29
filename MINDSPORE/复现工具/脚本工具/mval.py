# -*- coding: utf-8 -*-
"""多 value 堆布局实验：value a 溢出（dims=-5, 256B 可辨识 pattern 0x41），
value b 正常 Tensor（dims=[2], 8B, pattern 0x42）。观察 a 的越界写是否波及 b。"""
import subprocess, hashlib
from mindspore.train.checkpoint_pb2 import Checkpoint


def build(fn, pairs):
    msg = Checkpoint()
    for tag, dims, cb, pat in pairs:
        v = msg.value.add(); v.tag = tag
        v.tensor.tensor_type = "Float32"
        v.tensor.dims.extend(dims)
        v.tensor.tensor_content = bytes([pat]) * cb
    open(fn, "wb").write(msg.SerializeToString())


CASES = {
    "mval_ab": [("a", [-5], 256, 0x41), ("b", [2], 8, 0x42)],
    "mval_ba": [("b", [2], 8, 0x42), ("a", [-5], 256, 0x41)],
    "mval_3v": [("a", [-5], 256, 0x41), ("b", [2], 8, 0x42), ("c", [3], 12, 0x43)],
    "mval_silent": [("a", [-5], 24, 0x41), ("b", [2], 8, 0x42)],
}

for name, pairs in CASES.items():
    fn = f"/tmp/{name}.ckpt"
    build(fn, pairs)
    code = f"from mindspore import load_checkpoint; load_checkpoint('{fn}'); print('RETURN-NORMALLY')"
    r = subprocess.run(["/home/kaltsit/ms_env/bin/python", "-c", code],
                       capture_output=True, text=True, timeout=60)
    tail = (r.stderr or "").strip().splitlines()[-2:]
    print(f"{name}: rc={r.returncode} stdout={r.stdout.strip()!r} stderr_tail={tail}")
