# MindSpore load_checkpoint 堆缓冲区溢出（CWE-787）—— 变体审计发现（2026-08-07）

> 环境：WSL2，MindSpore 2.8.0 与 2.10.0（最新）实测；master 源码（jsdelivr 拉取）确认根因
> 发现方式：对已知 DoS（CWE-789）做 dims 变体审计时，发现 **内容长度 > dims 期望大小 → 堆溢出**
> **性质：全新漏洞，比已知 DoS 严重得多（内存破坏），2.8.0 / 2.10.0 / master 均未修**

---

## 一、漏洞概述

- **类型**：CWE-787 越界写（堆缓冲区溢出）
- **入口**：`mindspore.load_checkpoint()` → `train/serialization.py::_load_into_param_dict` → `Tensor_.convert_bytes_to_tensor()`（C++）
- **触发**：`.ckpt` 中 `tensor.dims` 很小（如 `[2]`），但 `tensor_content` 实际长度很大（如 256 字节）→ 按 dims 分配 8 字节缓冲，却写入 256 字节
- **与已知 DoS 的关系**：**同一根因、两种表现**
  - dims 大 + 内容小 → 分配过大 → **DoS**（CWE-789，已知漏洞，40GB 分配）
  - dims 小 + 内容大 → 小缓冲写大数据 → **堆溢出**（CWE-787，本发现）
  - 共同根因：`tensor_content` 长度**从不校验**是否等于 dims 推导的期望大小

---

## 二、复现（PoC：`poc_heapoverflow.ckpt`，279 字节）

构造：`dims=[2]`（Float32，期望 8 字节），`tensor_content = 256 字节`（64 个 float 1.0）

```python
from mindspore.train.checkpoint_pb2 import Checkpoint
msg = Checkpoint()
v = msg.value.add()
v.tag = 'x'
v.tensor.tensor_type = 'Float32'
v.tensor.dims.extend([2])                  # 期望 2*4 = 8 字节
v.tensor.tensor_content = b'\x00\x00\x80\x3f' * 64   # 实际 256 字节 = 32 倍
open('poc_heapoverflow.ckpt','wb').write(msg.SerializeToString())
```

触发（`run_variant.py` = 仅调用 `load_checkpoint`）：

```
$ python run_variant.py variants/big_content.ckpt
RETURN-NORMALLY                          # load_checkpoint 本身返回成功！
free(): invalid next size (fast)         # glibc 在析构/free 时捕获堆破坏 → Aborted (core dumped)
```

**关键点**：load_checkpoint **不报错直接返回**，堆破坏在 Python 解释器关闭、tensor 析构时暴露 → 崩溃发生在**任何调用者代码之后**，完全不可防御。

---

## 三、根因链（源码铁证，master `ccsrc/pybind_api/ir/tensor_py.cc`）

### 3.1 `ConvertBytesToTensor`（538-548 行）

```cpp
TensorPtr TensorPy::ConvertBytesToTensor(const py::bytes &bytes_obj, const py::tuple &dims, const TypePtr &type_ptr) {
  ShapeVector shape;
  for (size_t i = 0; i < dims.size(); ++i) {
    shape.push_back(dims[i].cast<int>());
  }
  TypeId data_type = type_ptr ? type_ptr->type_id() : TypeId::kTypeUnknown;
  tensor::TensorPtr tensor = std::make_shared<tensor::Tensor>(data_type, shape);  // ← 按 dims 分配
  const char *tensor_buf = PYBIND11_BYTES_AS_STRING(bytes_obj.ptr());             // 源 = 内容
  char *tensor_data_buf = reinterpret_cast<char *>(tensor->data_c());             // 目标 = dims 大小缓冲
  CopyFromBuffer(tensor_data_buf, tensor->Size(), tensor_buf,
                 PYBIND11_BYTES_SIZE(bytes_obj.ptr()), data_type);                // ← 拷贝
  return tensor;
}
```

### 3.2 `CopyFromBuffer`（504-537 行）—— 漏洞本体

```cpp
void CopyFromBuffer(char *dst, size_t dst_size, const char *src, size_t src_size, TypeId data_type) {
  bool fp16_in_fp32 = (data_type == TypeId::kNumberTypeBFloat16) && (dst_size * 2 == src_size);
  if (fp16_in_fp32) {
    // bf16 特判分支 —— 【08-07 已验证：有界，安全】
    // 条件 dst_size*2==src_size 保证写入总量 = elem_num*2 = (src_size/4)*2 = src_size/2 = dst_size
    // → 正好写完，永不越界。src 读取同样有界（src+2+i*4，末位 = src+src_size）
    ...
  } else {
    size_t remain_size = src_size;             // ←★★★ 拷贝长度 = 内容长度（攻击者控制）
    auto dst_ptr = dst;
    auto src_ptr = src;
    while (remain_size > SECUREC_MEM_MAX_LEN) {
      auto ret = memcpy_s(dst_ptr, SECUREC_MEM_MAX_LEN, src_ptr, SECUREC_MEM_MAX_LEN);
      ...
      remain_size -= SECUREC_MEM_MAX_LEN;
      dst_ptr += SECUREC_MEM_MAX_LEN;          // 目标指针推进 src 那么多
      src_ptr += SECUREC_MEM_MAX_LEN;
    }
    if (remain_size != 0U) {
      auto ret = memcpy_s(dst_ptr, remain_size, src_ptr, remain_size);  // ←★★★ 把 src 长度当 dest 缓冲大小传给 memcpy_s
      ...
    }
  }
}
```

### 3.3 为什么安全函数被绕过

- `memcpy_s(dst, size, src, n)` 的第二个参数本应是 **dest 缓冲的剩余大小**，用于安全检查
- 代码传入的是 `remain_size`（= src 剩余长度），**`dst_size` 参数在非 bf16 分支从未被读取**
- 结果：`memcpy_s` 相信"目标缓冲有 src_size 大"，实际只有 dims 推导的 `tensor->Size()` 大
- **src_size > dst_size 时 → 堆溢出**，且 `memcpy_s` 不会拦截（它不知道真实 dst 大小）

### 3.4 完整数据流

```
.ckpt protobuf → tensor.dims=[2], tensor_content=256B（攻击者控制）
  → shape=[2]
  → make_shared<Tensor>(Float32, [2])     // data_size_ = SizeOf([2]) = 2 元素 = 8 字节
  → tensor->data_c()                      // 懒分配 8 字节（TensorDataImpl::data()）
  → CopyFromBuffer(dst=8B, dst_size=8, src=256B, src_size=256, Float32)
      → memcpy_s(dst, 256, src, 256)      // 写 256 字节进 8 字节缓冲 = 越界 248B
  → heap 元数据被破坏 → free() 时 glibc 检测 → 崩溃
```

---

## 四、复现证据

### 4.1 glibc 堆破坏检测（两个版本）

| 版本 | 结果 |
|------|------|
| **2.8.0** | `RETURN-NORMALLY` → `free(): invalid next size (fast)` → Aborted (core dumped) |
| **2.10.0（最新）** | `RETURN-NORMALLY` → `free(): invalid next size (fast)` → Aborted (core dumped) |
| 2.8.0 + `MALLOC_CHECK_=3` | 同样 Aborted（glibc 加强检测确认） |

### 4.2 边界测试（dims=[2] 期望 8 字节，改变内容长度）

| 内容长度 | 越界量 | 结果 |
|---------|-------|------|
| 8 B | 0 | ✅ 正常 |
| 12-24 B | 4-16 B | 静默（写入 heap 空隙，未触发检测） |
| **≥32 B** | **≥24 B** | 🔥 **稳定崩溃**（`free(): invalid next size` / SEGV） |

→ 越界写 ≥24 字节时稳定破坏 malloc chunk 元数据 → 崩溃必现。

### 4.3 gdb 崩溃栈（下游症状）

```
Thread 1 "python" received signal SIGSEGV
0x... in _int_malloc (...)        ← 分配 36 字节都 SEGV
  → operator new → std::string 构造
  → mindspore::pipeline::ClearAttrAndMethodMap()
  → Py_FinalizeEx                  ← 解释器关闭时，malloc arena 已被越界写破坏
```

栈里没有 memcpy 写点，因为**越界发生在更早的 CopyFromBuffer（load_checkpoint 内部）**，崩溃只是 heap 元数据被破坏后的下游表现。

---

## 五、与已知 DoS 的对比（同一根因，两种表现）

| | 已知 DoS（CWE-789） | 本发现（CWE-787） |
|---|---|---|
| dims | 大（如 [1e5,1e5,1]） | 小（如 [2]） |
| content | 小（4B） | 大（256B） |
| 现象 | 尝试分配 40GB → OOM | 8B 缓冲写 256B → 堆破坏 |
| 触发点 | 分配阶段 | 拷贝阶段 |
| 影响 | DoS | **内存破坏（潜在 RCE）** |
| 修复状态 | 2.8.0+2.10.0 未修 | **2.8.0+2.10.0+master 均未修** |

**结论**：DoS 是"分配过大"，堆溢出是"拷贝过长"，同源于 `tensor_content` 长度不校验。修复应同时覆盖两点。

---

## 六、严重性与可利用性评估

- **CVSS 预估**：本地加载恶意 .ckpt，可导致任意代码执行（若溢出被精确利用）或可靠 DoS → **High~Critical**（视可利用性）
- **利用场景**：HuggingFace/ModelScope 投毒模型 → 用户 `load_checkpoint` → 进程崩溃；进一步：溢出内容可覆盖 heap 对象，有升级 RCE 的可能（现代 glibc 下需要堆风水，难度中高，但作为学术成果已充分）
- **为什么未被发现**：DoS 已知但"拷贝不校验长度"这一侧从未被系统性审计过；`dst_size` 未使用是明显的代码异味，但需要"小 dims + 大 content"这个组合才能触发
- **攻击面**：任何加载 .ckpt 的 MindSpore 用户，含具身智能场景中模型权重加载

---

## 七、修复建议（可附在上报材料）

1. `ConvertBytesToTensor` 或 `CopyFromBuffer` 入口处校验：`PYBIND11_BYTES_SIZE(bytes) == tensor->Size()`，不匹配直接抛异常（参照同文件 `CopyData(shape, data, data_len)` 的 `size * sizeof(T) != data_len` 检查）
2. `CopyFromBuffer` 的 `memcpy_s` 第二个参数应传 **dst 剩余大小**，而不是 src 剩余大小
3. 至少：`dst_size` 参数必须被读取并作为上限（非 bf16 分支）

---

## 八、产物

| 文件 | 说明 |
|------|------|
| `poc_heapoverflow.ckpt` (279B) | dims=[2] + 256B 内容，触发堆溢出 |
| `tensor_py_master.cc` | master 源码（含漏洞函数） |
| `variants/` (20 个) | dims 变体矩阵（边界测试用） |
| `craft_variants.py` / `run_variant.py` / `batch_variants.py` / `boundary_test.py` | 复现脚本 |
| `漏洞分析-MindSpore-DoS-2026-08-07.md` | 已知 DoS 分析（本发现的上游背景） |

---

## 九、下一步

- [ ] 上报：与 DoS 一起整理上报材料（华为 PSIRT / CNVD）——**堆溢出优先级高于 DoS**
- [x] ~~验证 bf16 特判分支是否同样越界~~ → **已验：有界安全**（条件 `dst_size*2==src_size` 保证写入=src_size/2=dst_size，测试 bf16_d2_exact8/d4_exact16/d8_exact32 全 clean；bf16 下溢出仍只在 else 分支）
- [ ] 尝试最小化可利用 PoC（能否让溢出落到可控制地址）
- [x] ~~检查 `load()` / safetensors 路径是否有同款 `CopyFromBuffer`~~ → **已验（08-07 晚）：见下方「十、家族审计」**

---

## 十、家族审计结论（2026-08-07 晚，用户要求深挖同款漏洞）

### 10.1 CopyFromBuffer 是**单点入口**（tensor_py.cc 内仅一个调用者）

- `CopyFromBuffer` 在 `tensor_py.cc` 里**只有 1 个调用者**：`ConvertBytesToTensor`（547 行）
- 全 Python 包 grep `convert_bytes_to_tensor` → 只有 serialization.py:1279 一个真实调用点（另一处是 pijit whitelist 登记，非调用）
- → **ckpt 加载链是唯一触发面**，没有第二个"同款 CopyFromBuffer"入口

### 10.2 所有 .ckpt 加载入口都收敛到同一个漏洞点

| 入口 | 走向 | 是否受影响 |
|------|------|:---:|
| `load_checkpoint()` | `_load_into_param_dict` → 1279 `convert_bytes_to_tensor` | ✅ 漏洞 |
| `load_checkpoint_async()` | 线程池调 `load_checkpoint`（相同格式分支） | ✅ 漏洞 |
| `load()` (MindIR) | `load_mindir`（C++ 独立解析链，**不走** CopyFromBuffer） | ⚠️ 独立家族，待审 |
| safetensors 格式 | `_fast_safe_open`（safetensors 库）→ `Tensor.from_numpy` | ⚠️ 不经 CopyFromBuffer，边界在库内 |

### 10.3 Python 侧零校验（防线只有 C++ 一处，且被绕过）

- `_load_into_param_dict`（serialization.py:1268-1279）：
  ```python
  data = element.tensor.tensor_content   # 攻击者控制
  dims = element.tensor.dims             # 攻击者控制
  ...
  param_data = Tensor_.convert_bytes_to_tensor(new_data, tuple(dims), ms_type)
  ```
- **没有任何 `len(content) == prod(dims)*itemsize` 校验**
- `_parse_ckpt_proto` 只做 `ParseFromString`（protobuf 解码），无 content/dims 关联校验
- `'str'` 类型分支：`str_length = len(data)/4` → `np.frombuffer(new_data, np_type)` —— np.frombuffer 会按 shape 越界吗？实际 dims 未用于 np_type，字符串长度由 content 决定 → 相对安全，但可作为后续审计项

### 10.4 另一处 memcpy_s 疑点已排除（MemCopyFromCacheToHost，450 行）

- `FlushFromCache` 路径：`host_offset = single_col_bytes * LongToSize(key_)`，只查了源边界 `cache_offset+single_col_bytes <= cache_max`，`host_max - host_offset` 若下溢会成巨值
- **但** `LongToSize` 对负值有保护（抛异常/返回 SIZE_MAX），且该路径需要 `tensor.cache_enable()` + hashmap tensor（**非文件解析入口**）→ 攻击面窄，暂不上报项

### 10.5 公开状态核查（决定上报价值的关键事实）

- **已知 DoS（CWE-789）**：HF 公开 PoC（ericblackgachara/mindspore-dos-poc，CVSS 7.5），描述声称**已报厂商**；涉及 ConvertBytesToTensor/load_checkpoint 与 dims 不校验——**但只讲内存放大，绝口不提拷贝不校验/CopyFromBuffer**
- **堆溢出（CWE-787，本发现）**：**公开资料中无任何提及**（WebSearch 交叉确认）→ 这是真正的未公开空白
- 结论：**根因"tensor_content 长度不校验"的 DoS 侧已知，但"拷贝侧内存破坏"表现完全未公开**——这正是可上报的新信息

## 附：bf16 分支验证记录（2026-08-07）

测试：`tensor_type='BFloat16'`，边界 case：

| case | dims (dst) | 内容 | 分支 | 结果 |
|------|-----------|------|------|------|
| bf16_d2_exact8 | [2] (4B) | 8B (2x) | bf16 | clean |
| bf16_d2_4x16 | [2] (4B) | 16B (4x) | else | clean（12B 越界落 heap 空隙） |
| bf16_d4_exact16 | [4] (8B) | 16B (2x) | bf16 | clean |
| bf16_d4_15B | [4] (8B) | 15B | else | clean（7B 越界落空隙） |
| bf16_d4_32B | [4] (8B) | 32B (4x) | else | **CRASH**（24B 越界） |
| bf16_d8_exact32 | [8] (16B) | 32B (2x) | bf16 | clean |

**判别性测试（确认 bf16 分支真实执行）**：若 bf16 分支被跳过走 else，dims=[16]（dst=32B）+64B 内容将 32B 越界必崩；实测 clean → **分支确实触发且安全**。

结论：**bf16 特判分支数学上有界（写入总量恒等于 dst_size），无独立漏洞，且实测确认分支被执行**；溢出仅存在于 else 分支（content > dst_size），与 Float32 同根因、同触发阈值（≥24B 越界）。

---

## 十一、dims 截断/负值变体全矩阵审计（2026-08-07 晚，Task 2 测试）

### 11.1 cast<int> 截断假设被推翻

- int64→int32 超界（2147483648、-2147483649、99999999999）→ `cast<int>` 抛 RuntimeError，**无回绕** → 截断变体不存在（早期假设错误，已修正）
- 但 **int32 范围内的负 dims（-1、-5、-100、-2147483648）全部通过 cast** → 负值才是真实攻击面

### 11.2 全矩阵：6 dtype × 14 dims × 7 content 长度 = 588 case（2.8.0 实测）

C=CRASH / E=EXC（Python 异常）/ O=OK。除一处外 6 dtype 完全一致：

| dims | 4 | 8 | 16 | 24 | 32 | 64 | 256 |
|---|---|---|---|---|---|---|---|
| (empty) | O | O | O | O | C | C | C |
| 0 | O | O | O | O | C | C | C |
| 1 | O | O | O | O | C | C | C |
| 2 | O | O | O | O | C | C | C |
| 3 | O | O | O | O | C | C | C |
| 10 | O | O | O | O | O*/C | C | C |
| -1 | E | E | E | E | C | C | C |
| -5 | O | O | O | O | C | C | C |
| -100 | O | O | O | O | C | C | C |
| -2147483647 | O | O | O | O | C | C | C |
| -2147483648 | O | O | O | O | C | C | C |
| 2147483648 | E | E | E | E | E | E | E |
| -2147483649 | E | E | E | E | E | E | E |
| 99999999999 | E | E | E | E | E | E | E |

\* `dims=10 cbytes=32`：Float32=OK（Size=40B，chunk usable 40B 未越界），其余 5 dtype=CRASH（Size 10-20B，chunk 更小，越界覆盖 header）——**唯一跨 dtype 分歧，正是 itemsize 差异，反证模型自洽**。

### 11.3 崩溃阈值统一规律

- 阈值 = **写入字节数 > glibc chunk usable size**，而非 dims 期望大小
- 0 字节缓冲（负/零/空 dims）→ malloc 最小 chunk usable 24B：写 ≤24B 静默、写 ≥32B 覆盖相邻 chunk header → free()/malloc 检测崩
- dims=10 Float32 → chunk 40B：写 64B 才越界崩
- **"OK" ≠ 安全**：所有 content > SizeOf 的 OK case 实际都发生了越界写（静默堆污染），只是未触发 glibc 检测

### 11.4 ⭐ parameter.py 校验缺陷（新发现）

```python
# parameter.py:308
if -1 in self.shape:
    raise ValueError("All shape elements of the Parameter must be positive...")
```

- 校验**只查 shape 含 -1**，其他负值（-2/-5/-100/-2³¹...）全部绕过
- `dims=[-5]` + content=24B → **load_checkpoint 静默正常返回畸形 Parameter**（0 字节缓冲越界写 + 负 shape 对象存活）
- `dims=[-1]` → 抛 ValueError（EXC）→ 反而暴露
- **攻击含义**：`-5` 变体比 `-1` 更隐蔽——投毒 ckpt 可"正常加载"无异常且堆已被越界写；畸形对象被用户后续代码使用时可能二次触发

### 11.5 静默污染区量化

- 0 字节缓冲写 24B：chunk 内（不越界）
- 写 25-31B：越界 1-7B 覆盖相邻 chunk prev_size（静默，不触发检测）
- 写 ≥32B：越界 ≥8B 覆盖相邻 chunk size 字段 → free() 检测崩
- **任何 content > SizeOf 都是 CWE-787 越界写**（不论 glibc 是否抓到）

---

## 十二、RCE 尝试与可行性评审（2026-08-07 晚，Task 1 测试）

### 12.1 多 value 堆布局实验（2.8.0 实测）

| 布局 | 结果 | 说明 |
|------|------|------|
| [a溢出256B, b正常8B] | rc=-6 | free() 检测 SIGABRT（堆元数据破坏） |
| [b正常8B, a溢出256B] | 普通运行 rc=-11 SIGSEGV；gdb 下 SIGABRT@_int_free 或 SIGSEGV@_int_malloc | **控制流偏离**：_int_malloc 遍历被 0x41 污染的 fastbin fd |
| [a,b,c 三 value] | rc=-11 SIGSEGV | 同上 |
| [a 写 24B（不越界）, b] | rc=0 静默 | 布局正常 |

**关键证据**：
- 溢出字节**完全可控**（tensor_content 任意 pattern，实测 0x41）
- 被污染 chunk 进入 fastbin 后，`fd` 字段 = 0x4141... → 后续 malloc 解引用 → SIGSEGV@_int_malloc —— **攻击者字节进入 glibc 空闲链表 = fastbin/tcache 投毒原语成立**
- 崩溃模式 SIGSEGV/SIGABRT 不稳定 → 堆布局敏感（利用可靠性的最大障碍）

### 12.2 畸形对象二次触发（dims=[-5] 变体）

- `load_checkpoint` **静默正常返回**，`param.shape=(-5,)` 存活；`asnumpy()` 抛 ValueError "negative dimensions are not allowed"
- 危害叠加：加载时 0 字节缓冲已越界写 + 返回负 shape 畸形 Parameter（训练/save 二次异常）
- 对照 dims=[2] 正常：shape=(2,)，asnumpy 正常

### 12.3 RCE 可行性多视角评审（Workflow：3 视角 + 综合 + 对抗验证）

**评审结论汇总**：

| 视角 | 评级 | 核心判断 |
|------|------|----------|
| 堆利用专家 | POSSIBLE | 多阶段 tcache/fastbin 投毒→重叠写→asnumpy 任意读→FSOP；但单发不现实，需专家级拼装 |
| MindSpore 对象专家 | POSSIBLE | data 缓冲是叶子分配（地址低于 TensorImpl），前向溢出无法覆盖本 tensor 字段；真正破坏面是后续 chunk 元数据 + top chunk；最可能触发路径是 Parameter.asnumpy() 与 save_checkpoint（无界调用 data_c()+Size()） |
| 威胁模型专家 | LIKELY | 供应链投毒内存破坏是主要现实路径，**无需 RCE 即可 High 级上报**；对比 PyTorch CVE-2026-24747（CVSS 8.8，仅 torch 2.10.0 修）、TensorFlow CVE-2021-41221（7.8）；MindSpore 自家 CVE-2025-3144（3.3）是需预判的反例 |
| 综合 | POSSIBLE | 多阶段链理论可行；可靠 DoS+内存破坏已实锤，足以支撑 High 级上报，**勿降级为仅 DoS/medium** |
| **对抗验证** | **UNLIKELY** | **safe-linking 循环依赖**：构造受控 fd 需堆基址（fd=heap>>12^target），唯一泄漏源"重叠→asnumpy"本身需先有受控重叠 → 自举不成；"0x41 污染 fd 被解引用"证明的是攻击者字节进入空闲链表、默认结局是确定性崩溃而非受控重定向；部分覆盖被锁死在堆内 ±0xFF；多阶段在已损坏堆上不可靠。修正：RCE 链 UNLIKELY，但 **CWE-787 内存破坏本身真实**，应报 Medium-High 级可信内存破坏 |

**最终结论（对抗后修正）**：
1. **完整 RCE：UNLIKELY**——glibc 2.35 safe-linking + 无内置泄漏原语 + 一次性单进程无 ASLR 爆破窗口 + 循环依赖，构成硬墙
2. **CWE-787 堆内存破坏：真实、确定性、类型无关、崩溃可延迟到析构/后续 malloc、进程外远程触发** → 合格上报项
3. **评级建议**：Medium-High（可信内存破坏），不虚高为 POSSIBLE RCE，也不降级为仅 DoS/medium
4. 结构洞察（对抗验证最有价值点）：tensor 数据缓冲是**叶子分配**，前向溢出无法原位覆盖本 tensor 的 data_ptr/shape/refcount/vtable，只能破坏后分配 chunk 的元数据——这决定了利用上限

**PoC 完整性**：RCE 未实现（诚实声明）。已交付：确定性内存破坏 PoC（多布局）+ fastbin 链污染证据 + 畸形对象二次触发 + 多视角可行性评审。

---

## 十三、-5 畸形 Parameter 经网络路径的真实影响（方向 1 实验，2026-08-07）

**动机**：确认 dims=[-5] 畸形对象被 `load_param_into_net` 加载进真实网络后，训练/推理/保存各路径的实际行为——回答"畸形 ckpt 能否静默进入生产训练流程"。

### 13.1 场景矩阵（subprocess 逐场景隔离，WSL mindspore 2.8.0）

网络：单层 `nn.Dense(2,2)`，恶意参数 tag='unused'（不匹配）或 'fc.weight'（匹配真实权重）。CKPT 分两种 content 长度：
- **cb=4B**：纯畸形（0 字节缓冲，4B < chunk usable 24B → 不越界/静默）
- **cb=28B**：物理越界 4B（0 字节缓冲，写入越过 chunk 头，静默污染相邻 prev_size）

| 场景 | 恶意参数 cb | 结果 |
|------|------------|------|
| `load_param_into_net` 匹配 tag ('fc.weight') | 4B | **RuntimeError** "should have the same shape ... (2,2) ... shape (-5,)" —— 确定性异常（非崩溃，可被 catch） |
| 跳过 tag + 推理（unused） | 4B | **全正常** rc=0：`SKIP-INFER OK` + `INFER (4,2)` —— 畸形参数被 load_param_into_net 静默跳过 |
| 跳过 tag + 训练 3 步 | 4B | **全正常** rc=0：loss 0.8882→0.8448 正常下降 |
| 跳过 tag + `save_checkpoint` | 4B | **静默成功 rc=0**，但见 13.2 |
| 加载 + 8000 次 malloc（delayed） | 4B | **全正常** rc=0 |
| 仅加载（load_only） | 4B | **正常** rc=0，shape=(-5,) 存活 |
| 跳过 tag + 推理（unused） | **28B** | **业务全正常**（SKIP-INFER OK + INFER 正常输出），**进程退出时 rc=-6**：`free(): invalid next size (fast)` |
| 仅加载（load_only） | **28B** | 打印 `LOAD-ONLY OK` 后**进程退出 rc=-6**：`free(): invalid next size (fast)` |
| 正常对照 dims=[2] cb=8 | — | 全部场景 rc=0 正常 |

### 13.2 ⭐ save_checkpoint 对畸形参数：静默数据丢失（非二次投毒）

**根因**（serialization.py:517 `_write_parameter_bytes_data`）：
```python
bytes_value = value[2].get_bytes()   # shape=(-5,) 的 0 字节 tensor → b""
for i in range(0, len(bytes_value), chunk_size):  # range(0, 0, chunk) 一次不执行
    ...  # 什么都不写
```
- 循环体零次执行 → 文件被创建但**空写** → 无任何异常/警告，`save_checkpoint` 正常返回
- **单畸形参数 dict** → **0 字节空文件**（实测 38B→0B）
- **混合 dict（正常+畸形）** → 畸形参数**静默丢弃**，正常参数保留（实测 46B，仅 fc.weight 存活）
- **修正中间假设**：此前推测"save 写回 = 二次投毒传播"——**不成立**。畸形参数（0 字节数据）根本写不进 protobuf，**不存在通过 save_checkpoint 传播恶意 ckpt 的路径**。实际缺陷是**完整性**：受害者训练流程加载恶意 ckpt 后执行 save_checkpoint，**模型权重静默丢失**，无任何提示。

### 13.3 ⭐ 关键发现：28B 变体 = "业务成功 + 延迟崩溃"的隐蔽 DoS

- cb=28B 变体下，**加载、推理、全部业务逻辑都正常打印并返回**，仅在**进程退出**（析构/free 阶段）触发 `free(): invalid next size (fast)` → rc=-6
- 机制：0 字节缓冲（glibc 最小 chunk ~24B usable）写入 28B → 越过 chunk 头 4B 静默污染相邻 chunk 元数据 → 该相邻 chunk 在退出/后续释放时才被 free() 检测
- **危害**：恶意 ckpt 可被完整加载并"正常运行"推理/训练（产出看似有效的结果），堆已在后台被破坏，崩溃发生在**任意延迟点**（服务运行若干分钟后、保存时、退出时）。相比立即崩溃，排障困难、服务可能已产出错误结果、且符合"供应链投毒→延迟失效"的现实攻击画像。
- 与 13.1 结合：即使畸形参数因 tag 不匹配被 load_param_into_net **跳过**（业务完全不受参数影响），**加载时的 CopyFromBuffer 越界写已污染堆** → 延迟崩溃不可避免。**投毒在加载瞬间发生，与参数后续是否被使用无关。**

### 13.4 结论与影响评估

1. **畸形 ckpt 可静默进入生产训练/推理流程**：tag 不匹配时 load_param_into_net 跳过畸形参数，推理/训练全程"正常"；匹配时确定性 RuntimeError（异常非崩溃）。
2. **实际危害分两档**：
   - cb=4B 档：纯数据完整性破坏（save 静默丢权重）+ 后续 asnumpy 访问抛错——低危但隐蔽
   - cb≥25B 档：**加载即堆污染，业务看似正常，延迟崩溃**——中危隐蔽 DoS，且与漏洞主链（堆溢出）同根因，是 CWE-787 在"使用场景"的实锤表现
3. **对上报的意义**：补齐了"堆溢出 PoC 是单次 load_checkpoint 崩溃"的短板——现在有**场景级证据**证明投毒 ckpt 能穿过加载→推理→训练→保存全链路，破坏发生在任意延迟点。上报材料可引用 13.1-13.3。
4. save 静默丢数据是**独立完整性缺陷**（serialization.py 对负 shape Parameter 无校验，get_bytes() 空数据静默跳过），可作为附加项，但非安全主链。

**脚本归档**：cycle_test.py（传播闭环验证）、mix_save.py（混合 dict 保存）、exp_neg5.py / runner_neg5.py（场景矩阵）→ `脚本工具/`。
