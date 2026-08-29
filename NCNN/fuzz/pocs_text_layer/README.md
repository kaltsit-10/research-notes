# ncnn text .param 层头解析 — F1/F2 最小 PoC（2026-08-15）

> 复现：`wsl bash -c 'cd /home/kaltsit/vuln_repro/ncnn_fuzz && setarch x86_64 -R ./fuzz_param_cov -runs=1 -rss_limit_mb=4096 <poc>'`
> 构建：`fuzz_param_cov`（libFuzzer + ASan，coverage 版，见 `../build_cov.sh`）

## 背景

ncnn 文本 `.param` 层头解析 `Net::load_param()`（src/net.cpp）对 `blob_index` 与
`top_count` 缺少边界/符号校验，与 2026-08-07 报告 §三.5 的"text 版层头解析"
为**同一漏洞族**。本 PoC 是 fuzz 得到的最小确定性样本（26B / 24B），并精确定位
到崩溃行。

已知 Dos 类（CWE-789，`layer_count/blob_count > 65536` 或负环绕）已被 harness
guard 拦截，不在本批。

## F1 — bottom 越界 → heap-buffer-overflow（CWE-125/787）

文件：`F1_bottom_oob.param`

```
7767517
1 1
MVN x 2 0 a b
```

- 结构：`layer_count=1 blob_count=1` → `d->blobs.resize(1)`（128B）；层 `MVN` 声明
  `bottom_count=2`、两个 bottom 名 `a b`。
- 触发：bottom 循环（net.cpp:1438-1448）对每个未知 bottom 名执行
  `Blob& blob = d->blobs[blob_index]; blob_index++;`。`blob_count=1` 时 `blob_index`
  无界增长到 1 → `d->blobs[1]` 越界（128B 区域右边 0 字节）。
- 结果：`heap-buffer-overflow`，READ size 8 @ net.cpp:1443（`blob.name = std::string(...)`）
- 修复建议：bottom/top 循环前校验 `blob_index < blob_count`（镜像 afad533 在
  `load_param_bin` 的 `<=0` 检查，TEXT 路径漏修）。

## F2 — 负 top_count → length_error → abort（CWE-248/755 DoS）

文件：`F2_neg_topcount.param`

```
7767517
1 1
MVN x 0 -1 0
```

- 结构：`bottom_count=0 top_count=-1`。
- 触发：net.cpp:1456 `layer->tops.resize(top_count)` 无符号检查，负数 → `std::length_error`
  → `std::terminate` → 进程 abort。
- 结果：`terminate called after throwing an instance of 'std::length_error'`
- 修复建议：`top_count < 0 || bottom_count < 0` 时 return -1（与 afad533 同模式，TEXT 路径漏修）。

## 与用户已推送 afad533 提交的关系

afad533（2026-08-15 13:19）只修了 **BIN 路径 `load_param_bin`**（net.cpp:1689-1708 的
`<=0` 检查）。TEXT 路径 `load_param` 的同款检查缺失 → F1/F2 均为 TEXT 专属漏洞。
这是"vuln 2 (text layer header)"独立 PR 的具体 PoC。

## F3 — YoloDetectionOutput 未初始化 softmax 指针 → SEGV（CWE-457/476）

文件：`F3_ydo_uninit_softmax.param`（38B，2026-08-15 从 crash_cov/other/ 新发现）

```
7767517
1 1
YoloDetectionOutput x 0 0
```

- 根因：`yolodetectionoutput.cpp` 构造函数只设 `one_blob_only/support_inplace`，
  **没初始化 `ncnn::Layer* softmax;`**（yolodetectionoutput.h:30，裸指针）。`Layer`
  基类构造也不初始化它（layer.cpp）。
- 触发：harness 只调 `load_param_mem` 不加载 model → `create_pipeline` 永不执行 →
  `softmax` 保持垃圾值 → `Net` 析构 `Net::clear()`（net.cpp:2454）调
  `YoloDetectionOutput::destroy_pipeline`（yolodetectionoutput.cpp:47 `if (softmax)`）
  对垃圾指针解引用 → SEGV（yolodetectionoutput.cpp:47:18）。
- 结果：`ERROR: AddressSanitizer: SEGV`，栈 `destroy_pipeline ← Net::clear ← ~Net`。
- 修复建议：构造函数里 `softmax = 0;`（一行，CWE-457 未初始化指针）。这是**第三个
  独立漏洞**，与 F1/F2（层头解析缺校验）不同根因，位于 layer 实现而非 net.cpp。
- 注意：crash_cov/other/ 里另一个 70B 样本 crash-4a0abec 是 BIN 格式已知 96B
  NULL-deref 变体（paramdict.cpp:594 `dr.read(NULL)`），非新漏洞。
