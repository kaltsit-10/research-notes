import os
import numpy as np
import mindspore as ms
from mindspore import Parameter, Tensor, load_checkpoint, save_checkpoint
from mindspore.common.initializer import initializer

# 畸形参数：从恶意 ckpt 加载（真实攻击路径）
mal = load_checkpoint('/tmp/neg5_cycle0.ckpt')
p = mal[list(mal.keys())[0]]
print('malformed shape:', p.shape)

w = Parameter(initializer('normal', (2, 2), ms.float32), name='fc.weight')
print('normal shape:', w.shape)

d = {'fc.weight': w, 'malformed': p}
out = '/tmp/mix_save.ckpt'
save_checkpoint(d, out)
print('SIZE', os.path.getsize(out))

loaded = load_checkpoint(out)
print('LOADED keys:', list(loaded.keys()))
for k, v in loaded.items():
    print(' ', k, v.shape)
