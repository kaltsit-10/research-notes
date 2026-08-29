# -*- coding: utf-8 -*-
"""探针：直接调 convert_bytes_to_tensor，对比不同 dims 的 Tensor 构造行为。"""
import mindspore as ms
from mindspore import Tensor

for dims in [(-1,), (-5,), (0,), (), (10,), (2,)]:
    for cbytes in [4, 32, 64]:
        try:
            t = Tensor.convert_bytes_to_tensor(b"\x00" * cbytes, dims, ms.float32)
            print(f"dims={dims} cbytes={cbytes} -> OK shape={t.shape} size={t.size}")
        except Exception as e:
            print(f"dims={dims} cbytes={cbytes} -> EXC {type(e).__name__}: {str(e)[:100]}")
