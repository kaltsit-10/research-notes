# -*- coding: utf-8 -*-
"""单 case 完整 stderr 探针：-5 vs -1 差异根因。"""
import subprocess, hashlib
from mindspore.train.checkpoint_pb2 import Checkpoint


def run(dims_csv, cbytes):
    dims = [int(x) for x in dims_csv.split(",")] if dims_csv else []
    fn = "/tmp/sc_" + hashlib.md5(f"{dims_csv}|{cbytes}".encode()).hexdigest()[:10] + ".ckpt"
    msg = Checkpoint(); v = msg.value.add(); v.tag = "x"
    v.tensor.tensor_type = "Float32"
    v.tensor.dims.extend(dims)
    v.tensor.tensor_content = b"\x00" * cbytes
    open(fn, "wb").write(msg.SerializeToString())
    code = f"from mindspore import load_checkpoint; load_checkpoint('{fn}')"
    r = subprocess.run(["/home/kaltsit/ms_env/bin/python", "-c", code],
                       capture_output=True, text=True, timeout=60)
    print(f"=== dims={dims_csv} cbytes={cbytes} rc={r.returncode} ===")
    print(r.stderr[-1400:])
    print("---")


run("-5", 4)
run("-1", 4)
run("-5", 32)
run("-1", 32)
