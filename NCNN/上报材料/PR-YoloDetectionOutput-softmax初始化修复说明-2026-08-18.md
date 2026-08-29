# ncnn 修复 PR 提交包 — YoloDetectionOutput softmax 初始化（2026-08-18）

> 对应漏洞：`YoloDetectionOutput` 构造器未初始化裸指针成员 `softmax` → 析构时对垃圾指针解引用 SEGV（F3，CWE-457/476）
> 提交人：`kaltsit-10`（昵称；不出现真实姓名/组织）
> 状态：**已推 fork 分支 `fix/ydo-softmax-init`，待开 PR**；补丁 `git apply --check` 通过；
> 双构建 A/B 实测已完成（2026-08-18，见第五节）
> 补丁文件：同目录 `PR-YoloDetectionOutput-softmax初始化修复.patch`（1 行）

---

## 一、PR 信息

| 项 | 值 |
|---|---|
| **PR 标题** | `initialize softmax layer pointer in YoloDetectionOutput` |
| **分支名** | `fix/ydo-softmax-init` |
| **基准** | upstream main `946fe3fb`（2026-08-18；提交前 rebase 到最新 main） |
| **改动** | 仅 `src/layer/yolodetectionoutput.cpp` 构造器，+1 行 |

---

## 二、PR 描述（body，直接粘贴）

```markdown
## Summary

`YoloDetectionOutput::softmax` is a raw `ncnn::Layer*` member that is never
initialized in the constructor. When a `Net` is torn down without
`create_pipeline()` having run (for example, a caller that only loads the param
file and never loads weights), `Net::clear()` reaches
`YoloDetectionOutput::destroy_pipeline()`, which tests `if (softmax)` on an
indeterminate pointer and dereferences garbage — SEGV (CWE-457 uninitialized
pointer / CWE-476 null-pointer-like dereference).

## Changes

- initialize `softmax = 0;` in the constructor

## Why

A 38-byte text `.param` declaring a `YoloDetectionOutput` layer, loaded with the
param-only path (no model weights), drives a deterministic ASan SEGV on master
(stack: `destroy_pipeline ← Net::clear ← ~Net`). Layer subclasses generally
either initialize raw members or set them in `create_pipeline`; this one
declares the member in the header (`yolodetectionoutput.h:30`) but writes it
only in `create_pipeline`, so the load-param-only usage reads uninitialized
memory at teardown.

## Test

| input | before (master) | after |
|---|---|---|
| 38B param, `YoloDetectionOutput x 0 0`, param-only load | ASan SEGV in destroy_pipeline | clean exit, no crash |
| valid model file | loads OK | identical, no false positive |
```

---

## 三、commit message

```
initialize softmax member in YoloDetectionOutput constructor

the raw Layer* softmax member is never initialized. when a Net is torn
down without create_pipeline having run (param-only load), the destructor
calls destroy_pipeline which tests if(softmax) on an indeterminate pointer
and dereferences garbage -> SEGV. initialize to 0.
```

---

## 四、提交流程

1. **fork** Tencent/ncnn（GitHub）→ `git fetch upstream main` → 新建分支 `fix/ydo-softmax-init` 基于最新 main
2. 在构造器补一行 `softmax = 0;`（或 `git apply PR-YoloDetectionOutput-softmax初始化修复.patch` 后核对）
3. `git push origin fix/ydo-softmax-init` → GitHub 开 PR，body 粘贴第二节
4. **一个 PR 一个根因**：本 PR 独立于 TEXT 层头、paramdict 数组 len（不同文件、不同机制）
5. PoC 文件不随 PR 提交（保持私密直至修复公开）

---

## 五、验证矩阵

环境：WSL2 Ubuntu 22.04 x86_64，`build_asan`（ASan + RelWithDebInfo）。修复前 = 同源码未打补丁；修复后 = 应用本补丁重编译。同一 `loadpoc_verify` harness（`text` 模式调 `load_param`，param-only 不加载权重，`Net` 析构触发）。

| 输入 | 修复前 | 修复后 |
|---|---|---|
| `F3_ydo_uninit_softmax.param`（38B，`YoloDetectionOutput x 0 0`） | **exit 134**：ASan `SEGV on unknown address`（栈：`destroy_pipeline ← Net::clear ← ~Net`；`load_param` 先返回 ret=0） | EXIT 0，ret=0，析构干净无崩溃 |
| 合法模型 `examples/squeezenet_v1.1.param` | EXIT 0，ret=0 | EXIT 0，ret=0，**行为不变** |

> 2026-08-18 实测（WSL2，`loadpoc_verify_baseline` vs `loadpoc_verify_patched`）。F3 三次以上确定性复现。

---

## 六、与相邻 PR 的关系

| PR | 漏洞 | 位置 |
|---|---|---|
| PR-text 层头 | TEXT 层头 count/索引越界（F1/F2） | `src/net.cpp` `load_param` |
| PR-paramdict | 数组 len 未校验 → 96B NULL 解引用 | `src/paramdict.cpp` `load_param_bin` |
| **本 PR** | YoloDetectionOutput `softmax` 未初始化 → 析构 SEGV | `src/layer/yolodetectionoutput.cpp` |

- 与另外两个 PR 根因不同（layer 实现级初始化缺失，而非解析器边界校验），独立提交。
- 修复只影响 `YoloDetectionOutput` 层，无 API/ABI 变化（成员已在类内，仅加构造初始化）。
