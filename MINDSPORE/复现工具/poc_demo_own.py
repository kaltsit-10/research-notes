import sys, os
import mindspore as ms
from mindspore import load_checkpoint
print('[+] calling load_checkpoint on malicious ckpt...')
load_checkpoint('dos_moderate_own.ckpt')
print('[+] returned normally (no crash)')
