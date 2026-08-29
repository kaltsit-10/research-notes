# NCNN `load_param_bin` blob 索引越界写（新发现，未公开）

> 发现日期：2026-08-12
> 工具：`harness-writing` + `fuzzing-dictionary`（ncnn param fuzz 目标，libFuzzer + ASan）
> 复现环境：WSL2 Ubuntu 22.04，ncnn master `a4d2ea1`（与 07-22 oss-forensics 复核一致，**未修复**）
> 保密：PoC 本地私密，修复前不公开（遵循既有归档规则）

---

## 一、漏洞概要

| 项 | 值 |
|---|---|
| 位置 | `src/net.cpp` `Net::load_param_bin(const DataReader&)` — bottom/top blob 索引读取（实测行号 1805-1828，随 commit 浮动，以函数名为准） |
| 类型 | **CWE-787 越界写**（`blob.consumer = i`）+ CWE-125 越界读（`d->blobs[idx]`） |
| 入口 | `ncnn::Net::load_param_bin()`（.parambin 二进制模型文件） |
| 触发 | 攻击者可控的 `bottom_blob_index` / `top_blob_index` int32，零前置校验 |
| 影响 | **确定性内存破坏**（ASan 证实 OOB WRITE）+ 可靠进程崩溃 |
| 修复状态 | **未修复**（master a4d2ea1；git log 从未出现过 blob 索引范围守卫） |
| 公开 CVE | 无 |
| 已上报 | **否**（与 08-07 已报两处均不同，见下） |

---

## 二、根因

bin 解析器读取每个 layer 的 bottom/top blob 索引时**不做任何范围校验**：

```cpp
// src/net.cpp —— Net::load_param_bin（master a4d2ea1，行号 1805-1828）
int bottom_blob_index;
READ_VALUE(bottom_blob_index)          // 攻击者可控 int32，零校验
Blob& blob = d->blobs[bottom_blob_index];   // OOB 读
blob.consumer = i;                     // OOB 写 ← ASan 证实 WRITE @ 1810
layer->bottoms[j] = bottom_blob_index;
// ... top_blob_index 同样（1818-1828）
```

`d->blobs` 已按文件头 `blob_count` resize（1690-1708），但索引访问处没有任何 `0 <= idx < blob_count` 检查。

**对照 text 路径（`Net::load_param`，1436-1453）有部分防护**：
```cpp
int bottom_blob_index = find_blob_index_by_name(bottom_name);  // 名字查表
if (bottom_blob_index == -1) { ... blob_index++; }             // -1 兜底
```
text 侧通过名字查表 + `-1` 兜底间接限制了索引范围；**bin 侧直接裸读整数** → 教科书级"兄弟漏洞"（一处有防护、一处裸奔）。

## 三、与既有报告的关系（诚实核验）

| 已报/已知项 | 位置 | 是否覆盖本发现 |
|---|---|---|
| 漏洞1（08-07）：bin `ParamDict::load_param_bin` 数组 `len` 未校验 → 96B NULL 解引用 | `paramdict.cpp` | **否**（不同函数、不同机制：len vs blob 索引） |
| 漏洞2（08-07）：text 层头 `top_count` 越行读取 → `d->blobs[blob_index]` 越界 | `net.cpp` text 路径 | **否**（本发现是 bin 路径；text 的 blob_index OOB 属漏洞2 范畴） |
| CVE-2026-50144（已修）：ParamDict 负 ID 越界写 | `paramdict.cpp`（已加 `id<0||id>=MAX` 守卫） | **否**（修复未覆盖 net.cpp blob 索引） |

→ **本发现是独立第三处，未公开未上报未修复。**

## 四、复现

### PoC（`repro/ncnn_blobidx_oob_149B.parambin`，149 字节）

二进制布局（关键字段）：
```
offset  size  field                value
0       4     magic                7767517
4       4     layer_count          14080
8       4     blob_count           14080
12      4     typeindex            0 (AbsVal)
16      4     bottom_count         1572864 (0x00180000; 崩溃发生在第一个索引读取处，故无需更多文件字节)
20      4     top_count            0x09090900 (与崩溃无关; parser 先读 typeindex/bottom_count/top_count 再读 blob 索引)
24      4     bottom_blob_index[0] 0x09090909 (首个 bottom 索引; 越界 → OOB 写; 修复版报错 151587081=0x09090909 证实)
```

### 触发

```bash
./fuzz_param -runs=1 repro/ncnn_blobidx_oob_149B.parambin
```

### ASan 输出（3/3 确定性）

```
ERROR: AddressSanitizer: SEGV on unknown address 0x7b2200a88ca4 ...
The signal is caused by a WRITE memory access.
    #0 ncnn::Net::load_param_bin(ncnn::DataReader const&) src/net.cpp:1810:27
SUMMARY: AddressSanitizer: SEGV src/net.cpp:1810:27 in ncnn::Net::load_param_bin
```

### 崩溃可靠性说明（诚实标注）

- **149B PoC 确定性 SEGV**（3/3）：`idx=0x09090909` 远超 blob_count=14080，必然落在未映射页
- ⚠️ **变体文件更正（2026-08-15 字节复核）**：`_negidx`/`_p1idx` **不是 blob 索引变体**——`-1`/`2` 位于 **top_count** 字段（offset 20，parser 在 blob 索引之前读取）：`_negidx` 实际触发 `tops.resize(-1)` → `std::length_error` abort（**count 值未校验**，与 text 层头同类，非 blob 索引 OOB）；`_p1idx` 为截断文件（top_count=2 需 2 个 top 索引但文件耗尽）→ 无 OOB 无崩溃。**漏洞真实性以 149B 主 PoC 为准**

## 五、影响评估（保守）

- OOB **写**已由 ASan 证实（WRITE @ 1810，值 = layer 索引 i，偏移 = 攻击者控制）
- 攻击者获得**可控偏移 + 有界值**的写原语；能否稳定转化为利用依赖堆布局 → 不主张 I:H
- 可靠 DoS（149B 复现）+ 真实内存破坏 → 诚实评级约 **CVSS 5.5-6.5（Medium）**，与 text 层头漏洞同级，待厂商评估

## 六、修复建议

```cpp
// Net::load_param_bin 内，bottom/top 索引读取处
int bottom_blob_index;
READ_VALUE(bottom_blob_index)
if (bottom_blob_index < 0 || bottom_blob_index >= blob_count)
{
    NCNN_LOGE("invalid bottom_blob_index %d", bottom_blob_index);
    clear();
    return -1;
}
// top_blob_index 同
```

---

## 评估补充（2026-08-12，真实性 / 可复现性 / 上报价值）

### A. 真实性核验（对照实验，A/B 同字节流仅改索引）

构造与 149B PoC **字节级相同**的输入，仅把 blob 索引区（offset 24..EOF，含首个 `bottom_blob_index`）全归零：

| 输入 | Release 非 ASan（build_vuln, GCC） | ASan |
|---|---|---|
| 越界索引 `0x09090909` | **EXIT=139 SIGSEGV** | **EXIT=139 SEGV WRITE @ net.cpp:1810** |
| 合法索引 `0` | EXIT=0 `ret=-1` 无崩溃 | EXIT=1 `ret=-1` 无崩溃 |

→ 崩溃**确由 blob 索引越界引起**，排除其他成因。

### B. 可复现性核验（跨构建）

- **Release 非 ASan（厂商实测口径）**：149B PoC 3/3 + 1/1 确定性 SIGSEGV ✅
- **ASan**：3/3 确定性 SEGV WRITE @1810 ✅
- ⚠️ 诚实标注：`_negidx`/`_p1idx` 经字节复核**非 blob 索引变体**（见上节更正）；149B 主 PoC 两种构建均稳定崩。漏洞真实性（每次运行都发生 OOB 写）与崩溃可见性解耦。

### C. 原创性核验（双源）

- **gitee mirror HEAD 复核（2026-08-12 二次 `git ls-remote`）**：早期"远程 HEAD = `a4d2ea1`、上游未移动"的结论**已过期**——上游已推进至 `ed9466b`（"update glslang 20260810" #6897）。但该中间提交对 `src/net.cpp` 仅改 Vulkan int16 清理逻辑（~1351/1725），**blob 索引读取区（~1806/1810/1819）未加任何守卫** → 本漏洞在**当前 HEAD `ed9466b` 上仍存在**（`git show ed9466b:src/net.cpp` 复核）
- **CVE-2026-50144（2026-07 发布，CVSS 7.1 HIGH，GHSA-jxmc-3mv6-7pwr）**：修复 commit `5a0288f2` 在 paramdict.cpp 加 `id<0||id>=MAX` 守卫 → **本快照已含此修复，但未覆盖 net.cpp blob 索引**
- **公开渠道（WebSearch/CVE 库）只有 CVE-2026-50144 关于 ncnn 参数解析**，无任何 blob 索引越界的披露/PR → 未公开先例
- ⚠️ 证据更正：早期"git log 从未出现 blob 索引守卫"基于**浅克隆**（depth=1，无历史）——该说法撤回；有效证据是"当前 master 快照直接审读无守卫 + 远程 HEAD 未变 + 无公开披露"

### D. 上报价值判定

| 维度 | 与 CVE-2026-50144（7.1 HIGH）对比 | 本发现 |
|---|---|---|
| 写偏移 | 攻击者可控（负 id × sizeof(Param)） | 攻击者可控（idx × sizeof(Blob)，int32 全范围） |
| 写值 | **完全攻击者可控**（任意 int/float） | **受限**（`blob.consumer = i`，值=层索引，需大量前置层才大） |
| 根因位置 | paramdict.cpp（已修） | **net.cpp load_param_bin（未修）** |
| 判性 | CWE-787，已 HIGH 7.1 | CWE-787，诚实评级约 **Medium 5.5-6.5**（值原语弱于前者，不主张任意代码执行） |

**结论：真实存在 + 发行版构建确定性可复现 + 未公开未修复 → 值得上报**。建议作为**独立第三处**随 08-07 GHSA/TSRC 批次补报（补报时说明与 CVE-2026-50144 及已报两处的关系），或等厂商对上一批回复后按同一流程提交。

---

## 附：fuzz 基础设施（本发现产物）

| 文件 | 说明 |
|---|---|
| `fuzz_param.cc` | 双路径 harness（text `load_param_mem` + bin `fmemopen`+`load_param_bin`，共享 corpus；内置已知 DoS 守卫） |
| `ncnn_param.dict` | 200+ token（magic、层类型、-23300 键、边界整数、bin LE 字节） |
| `build.sh` | clang 14 + libFuzzer + ASan 构建（`-fopenmp=libgomp`） |
| `run.sh` | campaign 启动脚本 |

### ⚠️ 已知局限（必须诚实标注）

- libFuzzer 仅加载 **42 个 coverage 计数器**（全来自 harness 自身）→ **libncnn.a 无 coverage 插桩**，本次撞上纯靠字典 token + 变异运气，**非真正覆盖率引导**
- 要跑有效长 campaign，需用 `-fsanitize=fuzzer-no-link` 重建 libncnn.a（cmake 加 `-fsanitize-coverage=trace-pc-guard` 或 fuzzer-no-link + ASan），再链 harness
- 目标构建命令见 `build_cov.sh`（待建/见下节）

### 下一步（覆盖率引导重建命令）

```bash
# 1) 用 coverage 插桩重建 ncnn 静态库
cd /home/kaltsit/vuln_repro/ncnn/ncnn_src
mkdir -p build_fuzz && cd build_fuzz
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fsanitize=address -fsanitize-coverage=trace-pc-guard" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -fsanitize-coverage=trace-pc-guard" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
  -DNCNN_BUILD_TOOLS=OFF -DNCNN_BUILD_BENCHMARK=OFF -DNCNN_BUILD_EXAMPLES=OFF \
  .. && make -j$(nproc) ncnn

# 2) 链 harness
clang++ -std=c++11 -g -O1 -fsanitize=fuzzer,address -fopenmp=libgomp \
  -I build_fuzz/src -I src fuzz_param.cc build_fuzz/src/libncnn.a -lpthread -o fuzz_param_cov

# 3) 长 campaign
./fuzz_param_cov -dict=ncnn_param.dict -close_fd_mask=3 -max_len=262144 -max_total_time=86400 corpus/
```
