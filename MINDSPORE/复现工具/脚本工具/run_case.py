"""单个 case 测试 runner：dims, content_bytes, dtype -> verdict
用法: python run_case.py "dims_csv" content_bytes dtype
"""
import sys, subprocess, hashlib
from mindspore.train.checkpoint_pb2 import Checkpoint

dims_csv, cbytes, dtype = sys.argv[1], int(sys.argv[2]), sys.argv[3]
dims = [int(x) for x in dims_csv.split(",")] if dims_csv else []
fn = "/tmp/case_" + hashlib.md5(f"{dims_csv}|{cbytes}|{dtype}".encode()).hexdigest()[:12] + ".ckpt"
msg = Checkpoint(); v = msg.value.add(); v.tag = "x"
v.tensor.tensor_type = dtype
v.tensor.dims.extend(dims)
v.tensor.tensor_content = b"\x00" * cbytes
open(fn, "wb").write(msg.SerializeToString())
code = f"from mindspore import load_checkpoint; load_checkpoint('{fn}'); print('RETURN-NORMALLY')"
r = subprocess.run(["/home/kaltsit/ms_env/bin/python", "-c", code], capture_output=True, text=True, timeout=60)
out = (r.stdout + r.stderr).strip()
if r.returncode < 0:
    verdict = "CRASH"          # 负信号 = SIGABRT/SIGSEGV（free() 堆破坏/段错误）
elif "free()" in out or "Aborted" in out or "Segmentation" in out:
    verdict = "CRASH"          # 捕获到崩溃标记但 rc 不为负的兜底
elif r.returncode == 1:
    verdict = "EXC"            # Python 层异常（ValueError 等，可能掩盖已发生的 OOB 写）
elif r.returncode == 0:
    verdict = "OK"
else:
    verdict = f"RC{r.returncode}"
print(f"VERDICT={verdict} dims={dims_csv or '(empty)'} cbytes={cbytes} dtype={dtype}")
