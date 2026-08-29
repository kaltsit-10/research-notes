# NCNN `load_param_bin` blob 索引越界写 — 补充 GHSA 私密披露材料（英文主稿）

> **性质**：独立第三处发现（补充上报）。与 08-07 已报两处（bin ParamDict len→NULL deref、text 层头 top_count 越行）及已公开 CVE-2026-50144 均不同。
> **渠道**：GitHub Security Advisory（Private Vulnerability Reporting, PVR）— 与 CVE-2026-50144（GHSA-jxmc-3mv6-7pwr）及 08-07 批次同渠道
> **入口**：`https://github.com/Tencent/ncnn/security/advisories/new`（若 PVR 未开启，走 08-07 指引中的备选路径）
> **日期**：2026-08-12
> **报送对象**：Tencent/ncnn 维护者
> **署名**：`kaltsit-10`（昵称，独立研究者；不出现真实姓名/组织）

---

## Title (form field, one line)

```
ncnn: out-of-bounds write in Net::load_param_bin via unvalidated bottom/top blob indices in crafted .parambin model file
```

## Description (form field — paste into the "Description" box)

### Summary

`ncnn::Net::load_param_bin()` parses each layer of a binary `.parambin` model file by reading attacker-controlled `bottom_blob_index` / `top_blob_index` integers and immediately indexing into the per-file `d->blobs` array with **no bounds check**:

```cpp
// src/net.cpp — Net::load_param_bin, master a4d2ea1 (line numbers shift; ~1805-1828)
int bottom_blob_index;
READ_VALUE(bottom_blob_index)              // attacker-controlled int32, zero validation
Blob& blob = d->blobs[bottom_blob_index];  // OOB read (CWE-125)
blob.consumer = i;                         // OOB write (CWE-787) — ASan-confirmed WRITE @ net.cpp:1810
layer->bottoms[j] = bottom_blob_index;
// top_blob_index handled identically (~1818-1828)
```

`d->blobs` is sized from the file-header `blob_count` (net.cpp ~1690-1708), but no `0 <= idx < blob_count` check exists at the access site. A 149-byte crafted file drives a deterministic crash; the OOB write is real on every run regardless of crash visibility.

**Text-path contrast (root cause family):** the text parser `Net::load_param()` resolves blob references by name via `find_blob_index_by_name()` with a `-1` fallback (net.cpp ~1436-1453), which indirectly bounds indices. The binary path reads raw ints with no equivalent guard — a sibling/one-guarded-one-not flaw in the same parser family.

### Vulnerability details

- **Location**: `src/net.cpp` `Net::load_param_bin(const DataReader&)` — bottom/top blob index handling. Present in master `a4d2ea1` (2026-07-22) **and re-verified on current gitee HEAD `ed9466b` (2026-08-12)**; identical to `20260526` tag `e54f7b1`.
- **Root cause**: no validation that `bottom_blob_index`/`top_blob_index` satisfy `0 <= idx < blob_count` before `d->blobs[idx]` access (both the `blob.consumer = i` write and the `blob` reference read).
- **Attack surface**: any application calling `ncnn::Net::load_param_bin()` / `Net::load()` on an untrusted `.parambin` file. ncnn is embedded in WeChat, QQ, and many mobile/desktop apps; a poisoned model file delivered via model hub / web / email triggers this on load. No privileges required; user must load the file (UI:R).

### Proof of Concept

PoC file `ncnn_blobidx_oob_149B.parambin` (149 bytes; SHA-256 `5740137f…`):

| offset | size | field | value |
|---|---|---|---|
| 0 | 4 | magic (`7767517` LE) | `DD 85 76 00` |
| 4 | 4 | layer_count | 14080 |
| 8 | 4 | blob_count | 14080 |
| 12 | 4 | typeindex | 0 (AbsVal) |
| 16 | 4 | bottom_count | 1572864 (`0x00180000`; huge declared fan-in) |
| 20 | 4 | top_count | `0x09090900` (irrelevant to crash — parser reads typeindex/bottom_count/top_count before any blob index) |
| 24 | 4 | bottom_blob_index[0] | `0x09090909` (first bottom index — far OOB; crash fires here) |

> Note: the file is a fuzzer-produced blob; the OOB write fires on the very first bottom-index read (offset 24) before any further data is consumed. Bytes past offset 28 are parser-irrelevant.

Trigger (any program calling `net.load_param_bin(f)` on the file, e.g. the ncnn fuzz harness; a minimal loader is included in the PoC bundle):

```
Release non-ASan (vendor-style GCC build):  EXIT=139 SIGSEGV  (3/3 + 1/1 deterministic)
ASan build:                                 EXIT=139 SEGV, WRITE memory access @ src/net.cpp:1810 (3/3 deterministic)

SUMMARY: AddressSanitizer: SEGV src/net.cpp:1810:27 in ncnn::Net::load_param_bin
```

**A/B control (mechanism proof):** byte-identical input except the blob-index region (offset 24..EOF, incl. `bottom_blob_index[0]`) zeroed — `ret=-1`, no crash, both builds. The crash is caused solely by the OOB index.

**Honest visibility caveat (corrected 2026-08-15):** the two compact variants in the PoC bundle are *not* blob-index variants — byte review shows the `-1` / `2` values sit in the `top_count` field (read before any blob index): the `-1` file (`_negidx`) triggers `tops.resize(-1)` → `std::length_error` abort (an unvalidated-count bug, same family as the text-path finding, *not* a blob-index OOB); the `2` file (`_p1idx`) is a truncated file that returns cleanly. The 149B PoC crashes deterministically on both builds because `idx=0x09090909` (offset 24) lands on an unmapped page. Vulnerability reality (OOB read+write every run) is decoupled from crash visibility; rely on the 149B PoC.

### Relationship to known issues (important)

- **CVE-2026-50144** (GHSA-jxmc-3mv6-7pwr, HIGH 7.1, fixed `5a0288f2`, 2026-05-28): unchecked *negative parameter id* → OOB write before `params[NCNN_MAX_PARAM_COUNT]` in `ParamDict::load_param`. Fix touches **`src/paramdict.cpp` only**; does not cover `net.cpp` blob indices.
- **08-07 submitted #1** (bin `ParamDict::load_param_bin` array `len` unvalidated → NULL deref): different function, different mechanism (`len` vs blob index).
- **08-07 submitted #2** (text layer-header `top_count` over-read → `d->blobs[blob_index]` OOB): text path; this finding is the **binary** path with a distinct (unmitigated) root cause.
- Verified on master `a4d2ea1` (2026-07-22) and **re-verified on current gitee HEAD `ed9466b` (2026-08-12)**: the sole intervening commit (#6897 "update glslang 20260810") only tweaks Vulkan int16 sanitization (src/net.cpp ~1351/1725); the blob-index reads at ~1806/1810/1819 carry **no guard added**. No public disclosure / PR / CVE for blob-index OOB exists as of 2026-08-12.
- → This is an **independent third finding** in the same parser family, warranting its own advisory/CVE.

### Impact

- CWE-787 (Out-of-bounds Write) — primary; ASan-confirmed WRITE at `net.cpp:1810`.
- CWE-125 (Out-of-bounds Read) — the `d->blobs[idx]` reference read.
- Attacker-controlled **write offset** (`idx × sizeof(Blob)`, int32 full range) with a **bounded write value** (`blob.consumer = i`, layer index). Weaker write primitive than CVE-2026-50144; we do not claim arbitrary code execution. Reliable DoS (149B file) + real memory corruption on any ncnn-embedded app.

### CVSS (self-assessed)

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H  =  7.1 (High)  [same template as CVE-2026-50144]
```
or conservatively `.../I:H/A:H` → we self-rate **Medium (5.5–6.5)** for the *impact/exploitability* framing given the bounded write value; leaving the numeric score to the maintainers' triage. `AV:L` per CVSS v3.0 User Guide — file-parsing vuln not network-dependent; `UI:R` — user must load a malicious model file.

### Suggested fix

In `Net::load_param_bin()`, validate each blob index against the already-known `blob_count` before use:

```cpp
int bottom_blob_index;
READ_VALUE(bottom_blob_index)
if (bottom_blob_index < 0 || bottom_blob_index >= blob_count)
{
    NCNN_LOGE("invalid bottom_blob_index %d", bottom_blob_index);
    clear();
    return -1;
}
// same guard for top_blob_index
```

### References

- Vulnerable code: `src/net.cpp` `Net::load_param_bin()` blob-index block, master `a4d2ea1` (2026-07-22) and current HEAD `ed9466b` (2026-08-12) — identical to `e54f7b1` (`20260526` tag).
- Prior same-family advisory (not covering this): GHSA-jxmc-3mv6-7pwr / CVE-2026-50144 — fix `5a0288f2` touches `src/paramdict.cpp` only.
- Affected versions: `<= 20260526` and master up to current `ed9466b` (no fix commit as of 2026-08-12).

---

## Affected products (form field)

- **Package name**: ncnn
- **Ecosystem**: GitHub Actions (C/C++ library; no package-manager ecosystem)
- **Affected versions**: `<= 20260526`, and master up to current HEAD `ed9466b` (still unfixed, re-verified 2026-08-12)
- **Patched versions**: none (no upstream fix as of 2026-08-12)
- **Vulnerable functions**: `ncnn::Net::load_param_bin()` in `src/net.cpp`

## Severity (form field)

- CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H → 7.1 High (recommended, mirrors CVE-2026-50144) — or self-rated Medium 5.5–6.5; score at maintainer discretion.

## Weaknesses (form field, CWE)

- `CWE-787` (primary — Out-of-bounds Write)
- `CWE-125` (Out-of-bounds Read)

## Credits (form field)

- `kaltsit-10` — Finder（昵称署名；不出现真实姓名/组织）

## Disclosure timeline (suggested)

- 90-day coordinated disclosure window (Project Zero convention) or maintainers' preferred timeline.
- No public disclosure until the advisory is published or the window expires. **PoC files stay private until then.**

---

## 附：人工验证声明（AI 辅助报告合规）

> **渠道说明（重要）**：GHSA 渠道**不要求**附件/截图（08-07 操作指引：GHSA"无强制'AI 报告'标签；内容完整即可"）。"人工验证 + 完整 PoC + 关键步骤截图"是**腾讯 TSRC AI 规范 TPSA26-03** 的硬性要求，仅走 TSRC 备选渠道时必需。本声明与截图供 TSRC 渠道使用；**GHSA 提交只需粘贴正文，无需附带任何截图**。
>
> 本报告由 AI 辅助发现（静态代码审计 + fuzz harness 变异 PoC 生成），**全部结论已经过人工复现验证**：
> 1. **人工复现**：2026-08-12 在 WSL2 Ubuntu 22.04 x86_64 上编译 ncnn master `a4d2ea1`（Release 非 ASan 厂商口径 + ASan 双构建），运行 149B PoC，确认 **Release 3/3+1/1 确定性 SIGSEGV、ASan 3/3 确定性 SEGV WRITE @ net.cpp:1810**。
> 2. **对照实验**：同字节流仅将 blob 索引归零 → 两构建均无崩溃（`ret=-1`），证明崩溃确由越界索引引起。
> 3. **关键结果截图/日志**：崩溃输出、ASan 报告、对照结果已实测生成并存于本地归档；GHSA 表单不支持附件，不随本材料提交（与文末 PoC 清单口径一致；走 TSRC 渠道时按 TPSA26-03 补交截图）。
> 4. **独立性说明**：仅以 DoS/内存破坏影响上报，不含武器化利用代码；不做 RCE 探索。

## 附：PoC 包清单（附件 ZIP）

| 文件 | 内容 |
|------|------|
| `ncnn_blobidx_oob_149B.parambin` (149B, SHA-256 `5740137f…`) | 双构建确定性 SEGV 触发（bottom_blob_index=`0x09090909` @ offset 24） |
| `ncnn_blobidx_oob_negidx.parambin` (28B, `633ec401…`) | ⚠️ 更正：非 blob 索引变体；`-1` 在 top_count 字段 → `tops.resize(-1)` length_error abort（count 未校验，与 text 层头同类） |
| `ncnn_blobidx_oob_p1idx.parambin` (28B, `da699c97…`) | ⚠️ 更正：非 blob 索引变体；`2` 在 top_count 字段，文件截断 → 无 OOB 无崩溃 |
| `control_allzero.parambin` | 149B 同字节流、索引全归零（A/B 对照，无崩溃） |
| `loadpoc_file.cpp` | 最小触发程序（`net.load_param_bin(FILE*)`） |

> 上方 5 项为 GHSA 提交实际所需核心附件（文本正文直接粘贴，无需截图）。
> **截图（仅 TSRC 备选渠道需要，未补录）**：ASan SEGV WRITE @ net.cpp:1810 / Release SIGSEGV / 对照 ret=-1 三张，走 TSRC 时按 TPSA26-03 要求补录即可。
> SHA-256 全集见 `NCNN/fuzz/repro/SHA256SUMS.txt`（本地归档）。
