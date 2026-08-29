"""MindSpore load_checkpoint dims x content 长度 x dtype 矩阵扫描。

用法: python matrix_scan.py <dtype[,dtype...]>   默认 Float32
输出: 每行 TSV: VERDICT\tdims\tcbytes\tdtype   (dims 空串显示为 (empty))
"""
import sys, subprocess, hashlib, concurrent.futures
from mindspore.train.checkpoint_pb2 import Checkpoint

DTYPES = sys.argv[1].split(",") if len(sys.argv) > 1 else ["Float32"]
# 覆盖：空 / 0 / 小正 / 负 int32 / int32 极值 / 超 int32（预期 cast<int> 抛 RuntimeError）
DIMS = ["", "0", "1", "2", "3", "10", "-1", "-5", "-100",
        "-2147483647", "-2147483648", "2147483648", "-2147483649", "99999999999"]
LENS = [4, 8, 16, 24, 32, 64, 256]
PY = "/home/kaltsit/ms_env/bin/python"


def one(dims_csv, cbytes, dtype):
    dims = [int(x) for x in dims_csv.split(",")] if dims_csv else []
    fn = "/tmp/case_" + hashlib.md5(f"{dims_csv}|{cbytes}|{dtype}".encode()).hexdigest()[:12] + ".ckpt"
    msg = Checkpoint(); v = msg.value.add(); v.tag = "x"
    v.tensor.tensor_type = dtype
    v.tensor.dims.extend(dims)
    v.tensor.tensor_content = b"\x00" * cbytes
    open(fn, "wb").write(msg.SerializeToString())
    code = f"from mindspore import load_checkpoint; load_checkpoint('{fn}'); print('RETURN-NORMALLY')"
    r = subprocess.run([PY, "-c", code], capture_output=True, text=True, timeout=60)
    out = (r.stdout + r.stderr).strip()
    if r.returncode < 0:
        verdict = "CRASH"
    elif "free()" in out or "Aborted" in out or "Segmentation" in out:
        verdict = "CRASH"
    elif r.returncode == 1:
        verdict = "EXC"
    elif r.returncode == 0:
        verdict = "OK"
    else:
        verdict = f"RC{r.returncode}"
    return f"{verdict}\t{dims_csv or '(empty)'}\t{cbytes}\t{dtype}"


def main():
    cases = [(d, l, t) for t in DTYPES for d in DIMS for l in LENS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(one, *c) for c in cases]
        for f in concurrent.futures.as_completed(futs):
            print(f.result(), flush=True)


main()
