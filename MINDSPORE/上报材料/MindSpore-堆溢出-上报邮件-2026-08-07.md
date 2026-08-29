# MindSpore `load_checkpoint()` 堆溢出（CWE-787）— 上报邮件草稿

> **渠道**：MindSpore 官方安全邮箱（唯一官方渠道）`mindspore-security@mindspore.cn`
> **⚠️ 必须 PGP 加密发送**：使用[官方 PGP 公钥](https://gitee.com/mindspore/community/blob/master/security/public_key_securities.asc)加密邮件
> **流程**：VMT（漏洞管理团队）处理 → 1 工作日内确认 → 7 天内详细回复 → 修复后以安全公告（SA）形式披露
> **日期**：2026-08-07
> **合规**：本报告为 AI 辅助挖掘，已人工验证（实机复现 PoC，见附件）；**PoC 在华为修复前不公开**（既定约束）

---

## 邮件主题

```
[MindSpore Security] Heap-buffer-overflow in load_checkpoint via unchecked tensor_content length (CWE-787)
```

---

## 邮件正文（按官方《疑似安全问题上报模板》）

### 1. 上报人信息

| 字段 | 内容 |
|------|------|
| 上报人 | kaltsit-10（网名，对外统一署名） |
| 联系方式 | 3270694207@qq.com（与发送邮箱一致） |
| 组织信息 | 个人研究者（独立上报，无单位） |
| 版本信息 | MindSpore 2.8.0、2.10.0、master（2026-08-07 拉取），**三版本均受影响** |
| 问题级别 | 严重问题（High，CVSS 自评 7.1，见下） |

### 2. 问题描述

**MindSpore `load_checkpoint()` 解析恶意 `.ckpt` 模型文件时存在堆缓冲区溢出（CWE-787），可致内存破坏。**

`.ckpt` 为 protobuf 格式，`TensorProto` 含两个攻击者可控字段：`dims`（声明张量形状）和 `tensor_content`（实际数据字节）。Python 侧 `serialization.py` **不做任何长度校验**，直接将两者传入 C++ `Tensor_.convert_bytes_to_tensor()` → `ConvertBytesToTensor`（`ccsrc/pybind_api/ir/tensor_py.cc:538-548`）→ `CopyFromBuffer`（`tensor_py.cc:504-537`）。

**根因**：`CopyFromBuffer` 中
```cpp
size_t remain_size = src_size;                              // 拷贝长度 = 攻击者控制的内容长度
auto ret = memcpy_s(dst_ptr, remain_size, src_ptr, remain_size);  // ★ src 长度被当作 dest 缓冲大小
```
`memcpy_s` 第二个参数本应传 **dest 缓冲剩余大小**（用于安全校验），但代码传了 `remain_size`（= src 剩余长度），**`dst_size` 参数在非 bf16 分支从未被读取**——安全函数被绕过。当 `tensor_content` 长度 > `dims` 推导的期望大小（`tensor->Size()`）时，向过小缓冲写入超量数据 → **堆溢出**。

**影响版本**：2.8.0 / 2.10.0 / master 实测全部可复现；跨数据类型（Float32/Float16/Int4/Int8/UInt8/Bool）均存在（588 case 矩阵验证）。

### 3. 发生场景

- 操作系统：Ubuntu 22.04 x86_64（WSL2 亦验证）
- 攻击场景：**HuggingFace / ModelScope 投毒模型权重** → 用户调用 `load_checkpoint` 加载 → 触发
- 无需任何权限；用户需主动加载文件（与官方 CVE-2026-24747 PyTorch 场景同构）

### 4. 影响范围

- 直接后果：glibc 堆元数据破坏 → 进程退出时 `free(): invalid next size (fast)` → **SIGABRT 确定性崩溃**
- 潜在后果：堆越界写（≥32B 越界稳定覆盖 chunk 头）具备内存破坏原语潜力，理论可升级任意代码执行（现代 glibc 下需堆风水，难度中高）
- **与 DoS 的同根关系**：同源（tensor_content 长度不校验）两种表现——`dims` 大 → CWE-789 内存放大（40GB，32B 文件）；`dims` 小 + content 大 → **CWE-787 堆溢出（本报告）**

### 5. 详细信息

**复现（已人工验证，2026-08-07，2.8.0）**：
```bash
python craft_poc.py float32     # 生成 poc_heapoverflow.ckpt (279B): dims=[2] 期望8B + 256B content（32倍）
python trigger.py poc_heapoverflow.ckpt
```
**实测输出**：
```
RETURN-NORMALLY                          # load_checkpoint 不报错返回（越界写已发生）
free(): invalid next size (fast)         # glibc 捕获堆破坏
Aborted (core dumped)                    # SIGABRT（rc=134）
```
关键：崩溃发生在解释器关闭、tensor 析构时，调用方**无法捕获/防御**。

**跨类型证据**（Int4）：
```bash
python craft_poc.py int4       # int4_d2_c64.ckpt (81B): dims=[2] qint4x2 期望1B + 64B content
# → 同样 free(): invalid next size
```

**受影响代码位置**（master）：
- `mindspore/ccsrc/pybind_api/ir/tensor_py.cc:504-537` `CopyFromBuffer`（`dst_size` 未读取）
- `mindspore/ccsrc/pybind_api/ir/tensor_py.cc:538-548` `ConvertBytesToTensor`
- `mindspore/train/serialization.py:~1268-1279`（Python 侧无校验）

### 6. 修复建议

1. **入口校验**（Python 侧）：`load_checkpoint` 前检查 `len(tensor_content) == prod(dims) * itemsize`，不符即拒绝
2. **C++ 侧**（根本修复）：`CopyFromBuffer` 中 `memcpy_s` 第二个参数传真实 dest 剩余大小，并校验 `PYBIND11_BYTES_SIZE == tensor->Size()`：

```cpp
// 修复示意（tensor_py.cc CopyFromBuffer 或 ConvertBytesToTensor）
if (PYBIND11_BYTES_SIZE(bytes_obj.ptr()) != tensor->Size()) {
    MS_LOG(EXCEPTION) << "tensor content size mismatch";
}
```

### 7. 上报者的漏洞披露计划

- 本报告为**私密披露**；PoC 与细节在贵方修复完成前**不会公开**
- 期望按贵方 VMT 标准流程处理（1 个工作日确认 / 7 天详细回复）
- 若贵方需要，可提供：完整 588 case 矩阵、ASan 报告、调试定位记录

### 8. 附件（PGP 加密邮件附件）

| 文件 | 说明 |
|------|------|
| `poc_heapoverflow.ckpt` (279B) | Float32 触发文件：dims=[2] + 256B content |
| `int4_d2_c64.ckpt` (81B) | Int4 跨类型证据 |
| `craft_poc.py` | PoC 构造脚本 |
| `trigger.py` | 触发脚本（仅调用 load_checkpoint） |
| `tensor_py_master.cc` (48KB) | master 源码（含漏洞函数 CopyFromBuffer / ConvertBytesToTensor） |
| `trigger_output.txt` | 实测崩溃日志（RETURN-NORMALLY → free(): invalid next size → Aborted） |
| `screenshot_heapoverflow.png` | 实测崩溃截图（2026-08-09 真实 X 截图：RETURN-NORMALLY → free(): invalid next size，与 trigger_output.txt 同一复现环境） |

---

## CVSS 自评参考

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H  =  7.1 (High)   ← 与 ncnn 同模板，正文统一采用
```
建议在邮件中自评 **High（7.1）**，注明以官方评估为准。
（脚注：若官方不采信"写原语潜力"，I 可下修至 L → 6.1。此处只列主推值，避免双值并存。）

---

## 提交操作要点

1. **PGP 加密**（必须）：下载[官方公钥](https://gitee.com/mindspore/community/blob/master/security/public_key_securities.asc)，用 `gpg --import` + `gpg --encrypt --recipient` 加密后发送
2. **发送至**：`mindspore-security@mindspore.cn`
3. **抄送**：不需要；邮件列表页面 https://mailweb.mindspore.cn/postorius/lists/mindspore-security.mindspore.cn/
4. **响应预期**：1 工作日内确认 → 7 天内详细回复 → 修复后 SA 公告
5. **身份**：可署团队名或真实姓名；若想匿名，联系 VMT 沟通（官方流程未见匿名选项，PGP 加密本身可保护内容）
6. **披露时间表**：邮件中已声明"修复前不公开"——与你的既定安全约束一致

> ⚠️ 与 ncnn（走 GHSA）不同：MindSpore 官方渠道是 **安全邮箱 + PGP**，不依赖 GitHub Advisory。GitHub API 确认 MindSpore **0 条历史 GHSA**，其漏洞披露走官方 cve-report 文档 + SA 公告，不是 GitHub CVE 体系。
