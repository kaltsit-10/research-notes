# ncnn 修复 PR 提交包 — ParamDict 数组 len 校验（2026-08-18）

> 对应漏洞：`ParamDict::load_param_bin` 数组分支 `len` 未校验 → 分配失败后空指针写（96B，CWE-476/787）
> 提交人：`kaltsit-10`（昵称；不出现真实姓名/组织）
> 状态：**【搁置】未开 PR**。上游已有 #6917 / #6918 / #6874 覆盖同一根因（paramdict 数组 len），
> 无需重复提交；本包保留作记录。补丁 A/B 实测已完成（2026-08-18，见第五节）。
> 补丁文件：同目录 `PR-paramdict数组len校验修复.patch`（12 行，两处守卫）

---

## 一、PR 信息

| 项 | 值 |
|---|---|
| **PR 标题** | `validate array length and allocation in ParamDict::load_param_bin` |
| **分支名** | `fix/paramdict-array-len` |
| **基准** | upstream main `946fe3fb`（2026-08-18；提交前 rebase 到最新 main） |
| **改动** | 仅 `src/paramdict.cpp` `ParamDict::load_param_bin` 数组分支，+12 行 |

---

## 二、PR 描述（body，直接粘贴）

```markdown
## Summary

`ParamDict::load_param_bin()` parses array parameters from a `.parambin` model
file. The array length `len` is an attacker-controlled int32 that is used
directly as `Mat::create(len)` with no validation. A crafted value such as
`INT32_MIN` symbol-extends to an exabyte-sized allocation that fails, leaving
`Mat::data` null, and the following `dr.read(ptr, sizeof(float) * len)` writes
through the null pointer — SIGSEGV (CWE-476 / CWE-787).

## Changes

- reject `len <= 0` before allocating
- after `Mat::create(len)`, bail out if the resulting Mat is empty
  (`data == NULL`), mirroring the defensive `v.empty()` pattern already used in
  `modelbin.cpp`

## Why

A 96-byte crafted `.parambin` drives a deterministic `Segmentation fault` on
current master (ASan: `allocation-size-too-big`). The sibling file
`src/modelbin.cpp` guards every `Mat::create()` with an empty check; the
`paramdict.cpp` array branches (binary path) do not. Note this is a different
root cause from the already-fixed CVE-2026-50144 (negative param id, also in
`src/paramdict.cpp`): that fix only guards `id`, not the array length, so a
negative/huge `len` still reaches `Mat::create`.

## Test

| input | before (master) | after |
|---|---|---|
| 96B array param, `len=0x80000000` | SIGSEGV (exit 139; ASan: allocation-size-too-big) | `ret=-1`, no crash |
| valid model file | loads OK | identical, no false positive |
```

---

## 三、commit message

```
validate array length and allocation in ParamDict::load_param_bin

the array branch reads an attacker-controlled len and feeds it to
Mat::create(len) without validation. a crafted value such as INT32_MIN
symbol-extends into an exabyte allocation that fails, leaving Mat::data
null, and the following dr.read(ptr, sizeof(float) * len) dereferences a
null pointer (SIGSEGV). reject len <= 0 and check the created Mat is not
empty, mirroring the modelbin.cpp defensive pattern.
```

---

## 四、提交流程

1. **fork** Tencent/ncnn（GitHub）→ `git fetch upstream main` → 新建分支 `fix/paramdict-array-len` 基于最新 main
2. 手动套用两处守卫（或 `git apply PR-paramdict数组len校验修复.patch` 后核对）；`git diff` 与补丁文件核对一致
3. `git push origin fix/paramdict-array-len` → GitHub 开 PR，body 粘贴第二节
4. **一个 PR 一个根因**：本 PR 只改 paramdict 数组 len；TEXT 层头与 YoloDetectionOutput 各独立 PR
5. PoC 文件不随 PR 提交（保持私密直至修复公开）

---

## 五、验证矩阵

环境：WSL2 Ubuntu 22.04 x86_64，`build_asan`（ASan + RelWithDebInfo）。修复前 = 同源码未打补丁；修复后 = 应用本补丁重编译。同一 `loadpoc_verify` harness（`bin` 模式调 `load_param_bin`）。

| 输入 | 修复前 | 修复后 |
|---|---|---|
| `poc96.parambin`（96B，数组 `len=0x80000000`） | **exit 134**：ASan `allocation-size-too-big 0xfffffffe00000044`（超 0x10000000000） | EXIT 0：`invalid array length -2147483648 (id=0)` → ret=-1 |
| 结构合法 `c_valid.parambin`（blob_count=2, idx=0） | EXIT 0，ret=-1（ParamDict 文件不完整，非本守卫） | EXIT 0，ret=-1，**行为不变、本守卫不误触发** |

> 2026-08-18 实测（WSL2，`loadpoc_verify_baseline` vs `loadpoc_verify_patched`）。poc96 三次以上确定性复现。

---

## 六、与相邻 PR 的关系

| PR | 漏洞 | 位置 |
|---|---|---|
| PR-text 层头 | TEXT 层头 count/索引越界（F1/F2） | `src/net.cpp` `load_param` |
| **本 PR** | 数组 len 未校验 → 96B NULL 解引用 | `src/paramdict.cpp` `load_param_bin` |
| PR-YoloDetectionOutput | softmax 成员未初始化 → 析构 SEGV | `src/layer/yolodetectionoutput.cpp` |

- CVE-2026-50144 修复 `5a0288f2` 只加 `id < 0` 检查，管不到本分支（id 合法、len 非法）；
  本补丁与 TEXT 层头 PR 均为**同一参数解析家族、不同根因**，独立提交便于维护者分别 review。
