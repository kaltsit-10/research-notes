# -*- coding: utf-8 -*-
"""dims=[-5] 畸形 Parameter 经网络使用路径的真实影响实验。

用法: python exp_neg5.py <scene> <ckpt>
场景:
  into_net     - 畸形 param tag='fc.weight' → load_param_into_net（shape 不匹配行为）
  skip_infer   - 畸形 param tag='unused' → 加载被跳过 + 正常推理
  skip_train   - 畸形 param tag='unused' → 加载 + 训练 3 步
  save         - 畸形 param → save_checkpoint 写回（二次投毒传播）
  delayed      - 畸形 param → 加载后大量 malloc（观察延迟崩溃）
  load_only    - 仅加载（对照，确认 rc=0）
"""
import sys
import numpy as np
import mindspore as ms
from mindspore import nn, Tensor, load_checkpoint, load_param_into_net, save_checkpoint

ms.set_context(mode=ms.PYNATIVE_MODE, device_target="CPU")


def build_net():
    class Net(nn.Cell):
        def __init__(self):
            super().__init__()
            self.fc = nn.Dense(2, 2)

        def construct(self, x):
            return self.fc(x)
    return Net()


def main():
    scene = sys.argv[1]
    fn = sys.argv[2]
    x = Tensor(np.random.rand(4, 2).astype(np.float32))
    label = Tensor(np.random.rand(4, 2).astype(np.float32))

    if scene == "into_net":
        net = build_net()
        p = load_checkpoint(fn)
        try:
            ret = load_param_into_net(net, p)
            print(f"INTO-NET OK ret={ret}")
            print("INFER", net(x).shape)
        except BaseException as e:
            print(f"INTO-NET EXC {type(e).__name__}: {str(e)[:200]}")

    elif scene == "skip_infer":
        net = build_net()
        p = load_checkpoint(fn)
        ret = load_param_into_net(net, p)
        print(f"SKIP-INFER OK ret={ret} param_count={len(p)}")
        print("INFER", net(x).shape)

    elif scene == "skip_train":
        net = build_net()
        p = load_checkpoint(fn)
        ret = load_param_into_net(net, p)
        loss_fn = nn.MSELoss()
        opt = nn.SGD(net.trainable_params(), learning_rate=0.01)

        def fwd(d, l):
            return loss_fn(net(d), l)

        gf = ms.value_and_grad(fwd, None, opt.parameters)
        for i in range(3):
            loss, grads = gf(x, label)
            opt(grads)
            print(f"TRAIN step{i} loss={float(loss):.4f}")
        print("TRAIN OK")

    elif scene == "save":
        p = load_checkpoint(fn)
        out = "/tmp/neg5_resaved.ckpt"
        save_checkpoint(p, out)
        print(f"SAVE OK -> {out}")

    elif scene == "delayed":
        p = load_checkpoint(fn)
        print(f"LOADED param={list(p.keys())} shape={p[list(p.keys())[0]].shape}")
        bufs = []
        for i in range(8000):
            bufs.append(bytearray(512))
        print("ALLOC-8000 OK")

    elif scene == "load_only":
        p = load_checkpoint(fn)
        k = list(p.keys())[0]
        print(f"LOAD-ONLY OK param={k} shape={p[k].shape}")


main()
