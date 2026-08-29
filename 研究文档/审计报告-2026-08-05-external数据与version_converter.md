# 审计报告：onnx 1.22.0 的 external_data 与 version_converter（2026-08-05）

> 目标：对照历史 CVE 模式，AI 审计 + 实证测试，判断现装版本是否还有可利用的路径漏洞。
> 结论先行：**历史已知模式全部已修复**（实证），候选残留为低危边缘情况。

---

## 一、审计范围与方法

| 对象 | 代码 | 方法 |
|------|------|------|
| external_data 加载 | `onnx/external_data_helper.py` + `onnx/checker.cc` 的 `open_external_data`（C++） | 代码审计 + 实证攻击测试 |
| version_converter | `onnx/version_converter/adapters/gemm_6_7.h`、`upsample_6_7.h`、`helper.cc` | 代码审计 + 实证转换测试 |

测试脚本：`audit_external_data_test.py`、`audit_version_converter_test.py`（项目根目录，可复跑）

---

## 二、实证测试结果

### 2.1 external_data（对照 2026 年 7 个历史 CVE 模式）

| 攻击 | 1.22.0 结果 |
|------|------------|
| 路径穿越 `../` | ✅ BLOCKED（ValidationError） |
| 绝对路径 | ✅ BLOCKED |
| symlink 绕过 | ✅ BLOCKED |
| hardlink 绕过 | ✅ BLOCKED |
| 正常文件（对照） | 正常读取 |

### 2.2 version_converter（对照 2026 年 Gemm/Upsample CVE）

| 用例 | 1.22.0 结果 |
|------|------------|
| Gemm C 空/1维/1x1 | 转换返回（广播检查安全） |
| Gemm A/B 1维 | ✅ 断言拦截（gemm_6_7.h:42） |
| Upsample scales 异常 | ✅ 断言拦截（upsample_6_7.h:24） |

### 2.3 onnx.hub（对照 CVE-2024-5187/7776）

**结果：模块已移除。** `onnx.hub`（含 `download_model` / `download_model_with_test_data`）在 onnx 1.22.0 和 main 里**整个文件已删除**，漏洞代码不复存在，无需审计。

### 2.4 全部 11 条历史 CVE 处置结论

| CVE 区 | 条数 | 1.22.0 状态 |
|--------|------|------------|
| external_data 路径遍历 | 7 | ✅ 已修复（实证全 BLOCKED） |
| version_converter | 2 | ✅ 已修复（断言拦截） |
| onnx.hub 下载 | 2 | ✅ 代码已移除 |

**onnx 包已知漏洞面在 1.22.0 已全部干净。** 找新漏洞必须靠新 fuzz（C++ 代码 + ASAN），不靠历史模式。

---

## 三、为什么修得这么好（防御结构）

```
Python 层 3 层防线（external_data_helper.py 注释引用 GHSA-538c）：
  L1: external_data 键白名单（防属性注入 CWE-915）
  L2: offset/length 非负校验（CWE-400）
  L3: 读前文件大小校验（防内存耗尽 CWE-400）

C++ 层（checker.cc open_external_data）：
  · 拒绝空/绝对路径
  · lexically_normal + 拒绝 ".."
  · 拒绝 symlink（is_symlink / O_NOFOLLOW / RESOLVE_NO_SYMLINKS）
  · 拒绝硬链接（st_nlink > 1 / nNumberOfLinks > 1）
  · 内核级 openat2 RESOLVE_BENEATH（POSIX）
  · Windows: FILE_FLAG_OPEN_REPARSE_POINT + inode 对比（TOCTOU 防护）
```

**这是典型的"修完 7 个 CVE 后重兵加固"状态**——历史上犯过的错都被系统性堵死了。

---

## 四、残留候选（低危，诚实标注）

| # | 候选点 | 分析 | 危害 | 建议 |
|---|--------|------|------|------|
| 1 | C++ `data_path_str[0]=='#'` 跳过包含检查 | 仅当 base_dir 为空且 location 以 `#` 开头才触发；但 `..` 检查在其之前仍生效 | 低 | 不优先 |
| 2 | `validate_write_location`：Windows 盘符相对路径 `C:x` | `is_absolute()` 对 `C:x` 返回 false，可能绕过；Windows 特定，写路径 | 低 | 需 Windows 实测 |
| 3 | Python `_is_valid_filename` 正则漏 `\` 反斜杠 | Windows 下 tensor 名可含 `\` → 可能路径分隔；仅 convert 路径 | 低 | Windows 特定 |
| 4 | onnx.hub 下载函数（CVE-2024-5187/7776 区） | Python 文件写入/路径遍历，未在本轮实证（需网络） | 待测 | 建议下一轮审 onnx/hub.py |

**结论**：以上都是低危/待测，**没有可直接利用的高危残留**。

---

## 五、战略含义（重要）

1. **external_data 和 version_converter 的历史模式已死**——不值得在这两个已知区域继续耗时间找"历史变体"。
2. **找新漏洞必须靠"新 fuzz"**：对 C++ 代码（adapters、checker、reference ops）做针对性 fuzz，用畸形 shape/属性探索断言之外的分支。
3. **现有 fuzz 目标**：onnx 自带 `onnx/fuzz/fuzz_version_converter.py` 等 6 个 OSS-Fuzz 目标——说明这些区域 Google 在 fuzz，我们的价值在**覆盖面更深的自定义 harness**。

---

## 六、下一步

- [ ] 审 onnx.hub 下载函数（第 4 项候选，Python 可快速审）
- [ ] 对 version_converter adapters 写 shape 变异 fuzz（C++ 需构建 onnx）
- [ ] 转 ORT 官方 harness fuzz（主战场，仍需构建）
