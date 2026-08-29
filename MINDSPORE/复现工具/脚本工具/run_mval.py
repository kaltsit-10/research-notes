import sys
from mindspore import load_checkpoint
load_checkpoint(sys.argv[1] if len(sys.argv) > 1 else "/tmp/mval_ba.ckpt")
