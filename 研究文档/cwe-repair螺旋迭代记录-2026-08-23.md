
## 第三十二轮：下一阶段 Perspective

### 核心方向

下一阶段不以 finding 数量为主要目标，而是将 cwe-repair 从本地规则集合逐步收敛为：

> 可复现、可审计、可迁移的输入契约验证组件。

架构分为四层：

```text
Deterministic Core
  detector / repair suggestion / verify / symmetry
Evidence Layer
  source version / location / input origin / guard evidence / repair pair
Evaluation Layer
  strict benchmark / negative set / regression fixtures / coverage
Optional LLM Layer
  context summary / classification suggestion / repair explanation
```

LLM 只能作为可替换审阅器，不能成为核心执行依赖。

### 优先级

1. 统一 CLI 和路径参数；
2. 正式化 Finding、RepairPair、VerificationResult schema；
3. 为每条主要规则建立 positive/guarded/fixed 三类对照样本；
4. 将 strict candidate、guard recognition、fixed-code regression、runtime verification 分开统计；
5. 将组件特化逻辑逐步移入 manifest 和 guard pattern 配置；
6. 只做有限跨文件证据，不宣称完整数据流分析；
7. 对 LLM 输出增加结构化校验，拒绝虚构文件、行号、状态和验证结论。

### 数据集规模原则

34 条 finding 适合作为第一版回归基准，但不应作为普适数据集。后续新增样本必须至少推动以下一项可验证改进：

- 新代码形态；
- 新的守卫负例；
- 修复前后对照；
- 新 repair requirement；
- 新双向验证输入；
- 版本/路径映射证据；
- 误报过滤或跨组件抽象。

高质量对照样本优先于单纯扩大数量。

### NCNN merge/fix PR 调研计划

下一步自主调研授权本地可获得的 NCNN merge/fix PR 记录，优先使用：

- 本地 patch、fix 文件和复现源码；
- 已存在的 `paramdict_vuln.cpp` / `paramdict_fix.cpp`；
- `net.cpp` 文本/二进制解析路径；
- PR 中的修复前后差异和 review 记录；
- 资源上限、索引边界、除零和路径对称性案例。

每个 PR 只在具备本地源码或明确本地 patch 时纳入严格回归；仅有远程描述时标记为 `external-reference`，不计入严格 benchmark，不推断当前版本状态。

调研闭环：

```text
定位 merge/fix PR
→ 确认本地 patch/源码
→ 提取 before/after
→ 建立 repair_pair
→ 生成 positive/guarded/fixed 对照
→ detector 前后扫描
→ symmetry_check
→ repair_evidence
→ cwe_verify（有本地二进制时）
→ 更新记录
```

### skill/plugin 边界

上述增强不背离 skill 初衷：核心仍是检测、证据分层、修复建议、对称性检查和双向验证。schema、benchmark、repair_pairs 和回归 fixture 属于可选支撑层，不阻塞单文件使用，也不把组件改造成依赖 LLM 的黑盒平台。

真正应避免的方向：

- 只追求 finding 数量；
- 把 benchmark 当准确率或召回率；
- 把理论 CWE 能力覆盖当作逐条运行闭环；
- 把静态守卫当作完整验证；
- 引入真实执行器、未授权网络投递或攻击链能力。

## 第三十三轮：NCNN PR-derived 规则与守卫回归

### 本地 PR 调研

复核本地材料：

- `NCNN/上报材料/PR-6922合并修复.patch`；
- `PR-blob索引修复.patch`；
- `PR-text层头校验修复.patch`；
- `PR-paramdict数组len校验修复.patch`；
- `PR-YoloDetectionOutput-softmax初始化修复.patch`；
- 对应 PR body、修复说明、复现源码和 A/B 记录。

`PR-6922合并修复.patch` 是本地 unified diff，涉及 `src/net.cpp`，新增 42 行，其中 9 行匹配计数上限、blob 索引和 shape-hint 守卫。patch 摘要工具明确标记 `source_proof=false`：本地 patch 是修复证据，不自动等同于当前源码已切换到该版本。

### detector 新增模式

基于本地 NCNN patch 新增并输出输入校验缺口和修复要求：

- `partial_param_id_guard`：仅有 `id >= NCNN_MAX_PARAM_COUNT` 的半边索引契约；
- `unchecked_blob_index`：`d->blobs[bottom_blob_index/top_blob_index]` 访问前缺少范围契约；
- `unchecked_parser_count`：解析计数直接进入 `resize`；
- `array_length_contract`：ParamDict 数组 `len` 直接进入分配和后续 I/O。

固定代码过滤只在有限的本地上下文中成立：需要同时找到对应的下限/上限、长度正值和分配结果检查；没有这些证据则保留候选。

### 客观对照结果

#### 合成 positive/fixed fixture

同一代码形态：

- before：`array_length_contract`、`unchecked_blob_index`、`unchecked_parser_count` 共 3 类命中；
- after：三类均有完整守卫，命中降为 0。

#### 真实本地 NCNN fixed 源码

`TOOLTEST_NCNN/net.cpp` 的 PR-derived 新模式：

```text
原始匹配：15
守卫过滤后：1
```

原始匹配分布：`unchecked_blob_index=3`、`unchecked_parser_count=5`、`divide_by_input=7`；过滤后仅保留 1 条文本路径候选：

```text
net.cpp:1463  Blob& blob = d->blobs[bottom_blob_index];
```

该访问位于 `load_param` 文本路径，PR-6922 的显式 blob 索引守卫只覆盖 BIN 路径，因此没有被强行过滤。按当前 fixed 源码样本计算，PR-derived 候选减少 `14/15`，但这不是准确率或召回率。

#### ParamDict 修复前后

```text
paramdict_vuln.cpp: partial_param_id_guard=2, array_length_contract=2
paramdict_fix.cpp:  partial_param_id_guard=0, array_length_contract=2
```

这准确反映：本地 `paramdict_fix.cpp` 只包含负 `id` 修复，不包含 `PR-paramdict数组len校验修复.patch`；数组 `len` 缺口仍被报告。

### 回归与基准边界

- cwe-repair regression：`PASS`；
- 全脚本 py_compile：`PASS`；
- dataset schema：34 findings、3 repair_pairs、`valid=true`；
- strict benchmark：`16/31`；
- 文件级参考：`20/31`；
- GUARDED：`3`。

严格 benchmark 未因 patch 记录、文件级相似或修复说明中的行号而抬高。PR-6922 已加入 `repair_pairs`，但标记为 `documented-local-ab-not-rerun`，不计入 leaderboard。

### 后续待办

- 审阅文本路径 `blob_index` 候选是否需要独立输入契约守卫；
- 将 ParamDict len patch 应用到独立本地 fixed fixture，再验证 `array_length_contract` 从命中到过滤；
- 继续从其他本地 merge/fix patch 提取 guarded/fixed 对照，不扩大理论指标口径。

## 第三十四轮：ParamDict len fixture 与文本层头契约

### ParamDict len 修复对照

根据本地 `PR-paramdict数组len校验修复.patch` 建立 reduced fixture：

```text
.dsh/skills/cwe-repair/examples/ncnn_paramdict_len_before.cpp
.dsh/skills/cwe-repair/examples/ncnn_paramdict_len_after.cpp
```

before/after 差异保留真实修复语义：

- `len <= 0` 在分配前拒绝；
- `Mat::create(len)` 后检查 `v.empty()`；
- 后续读取前保留错误返回。

扫描结果：

```text
before: array_length_contract 命中 1
after:  array_length_contract 命中 0
```

该 fixture 只有静态回归证据，运行摘要为 `REVIEW`，不冒充完整 ncnn 构建或运行验证。

### 文本层头候选

复核本地文本 PoC、源码和报告后确认：

- `Net::load_param()` 连续执行四次 `SCAN_VALUE`；
- 层头 token 不完整时，后续值可能从下一条输入记录继续读取；
- `top_count` 随后进入 `resize` 和文本 blob 生成路径；
- PR-6922 的显式 blob 索引守卫只覆盖 BIN 路径，不能过滤文本路径候选。

新增 `text_layer_header_contract` 规则及修复要求：

- 验证所有层头字段来自同一输入记录；
- 拒绝截断或额外 token 的层头后再使用 count；
- 规则只输出输入校验缺口和修复要求，不生成未经语义审阅的自动补丁。

真实 `TOOLTEST_NCNN/net.cpp` 命中位置：`load_param` 层头块约 `1396`。

### 回归与边界

- cwe-repair regression：`PASS`；
- dataset schema：34 findings、3 repair_pairs、`valid=true`；
- strict benchmark：`16/31`；
- 文件级参考：`20/31`；
- GUARDED：`3`；
- ParamDict len fixture：静态命中 `1 → 0`；
- 文本层头 fixture：候选命中；
- 对称性检查：当前 NCNN text/bin 文件返回 `symmetric=true`。

严格 benchmark 未因新 fixture、文本报告或历史行号被抬高。

## 第三十五轮：TEXT blob_index 与 Yolo 生命周期对照

### TEXT blob_index

本地 `NCNN/fuzz/pocs_text_layer/README.md` 的 F1 记录明确描述了 TEXT 路径中 `blob_index` 递增后直接访问 `d->blobs[blob_index]`，而 PR-6922 的索引守卫只覆盖 BIN 路径。新增：

- `text_blob_index_access` 检测模式；
- 修复要求：在每次 TEXT 路径 blob 访问前校验生成索引和 `blob_count` 容量；
- before/after reduced fixture：
  - `ncnn_text_blob_index_before.cpp`；
  - `ncnn_text_blob_index_after.cpp`。

对照结果：

```text
before: text_blob_index_access 命中
after:  完整 [0, blob_count) 守卫后过滤
```

真实 `TOOLTEST_NCNN/net.cpp` 当前保留文本路径候选，不将历史 BIN patch 误作 TEXT 修复证据。

### YoloDetectionOutput 生命周期对照

复核本地 `PR-YoloDetectionOutput-softmax初始化修复.patch` 和 A/B 记录，建立：

- `ncnn_yolo_softmax_before.cpp`；
- `ncnn_yolo_softmax_after.cpp`。

该案例属于构造器裸指针初始化/析构生命周期契约，不适合强行归入通用索引规则。只作为 `repair_pair` 静态证据：构造器新增 `softmax = 0`，无本地完整构建运行时不标记 verified。

### 本轮状态

- repair_pairs：`5`；
- cwe-repair regression：`PASS`；
- 全脚本 py_compile：`PASS`；
- dataset schema：`valid=true`；
- strict benchmark：`16/31`；
- 文件级参考：`20/31`；
- GUARDED：`3`。

新增 fixture 和历史修复材料均未计入严格 benchmark，也未改变 34 条 finding 计数。

## 第三十六轮：本地 patch 适配与路径范围证据

### 可重复 patch 适配检查

`repair_evidence.py` 新增隔离临时树检查：

```text
--source <本地源文件> --patch <本地.patch> --target-path src/<目标文件>
```

输出两个静态来源状态：

- `forward_applicable`：patch 可应用到映射后的本地前像；
- `reverse_applicable`：当前本地快照与 patch 后像相容。

它不修改原源码，且始终保留 `runtime_verdict=REVIEW`，不替代恶意拒绝/合法通过的双向运行验证。

### ParamDict patch 的实际范围

本地 `PR-paramdict数组len校验修复.patch` 的 hunk 目标是 `src/paramdict.cpp`，将重命名的本地复现源映射到该路径后：

```text
forward_applicable=true
reverse_applicable=false
array_length_contract: [297, 591] -> [297]
```

含义：补丁可与本地 BIN 前像 hunk-compatible，且只覆盖 `load_param_bin` 的 array 分支。补丁守卫顺序也已回归验证：`len <= 0` 在 `create(len)` 前，`.v.empty()` 在 `create` 后且 `dr.read(ptr, ...)` 前。

TEXT `load_param` 旧式数组分支约 297 行仍是 `candidate / needs-review`，不能标记为 fixed 或 guarded；本地 `paramdict_fix.cpp` 仅修负 `id`，其数组长度候选仍为 `[297, 591]`。同时该 BIN patch 没有显式正上限，不能据“候选减少”声称完整资源边界修复。

### TEXT count 与 token 契约区分

`PR-text层头校验修复.patch` 对当前 `TOOLTEST_NCNN/net.cpp` 同样满足：

```text
forward_applicable=false
reverse_applicable=true
```

新增 count-only before/after fixture 证明：该 patch 风格会过滤 `unchecked_parser_count`，但仍保留 `text_layer_header_contract`。因此 count 的符号/上限守卫不能被误写成“同一记录层头 token 契约已修复”。

### 回归与边界

- 删除 `text_layer_header_contract` 的无效重复规则项；
- schema 现校验 patch 适配元数据的本地 source/patch 路径与布尔类型；
- `symmetry_check.py` 对 `TOOLTEST_NCNN/net.cpp`：`symmetric=true`；
- cwe-repair regression：`PASS`；
- 全脚本 py_compile：`PASS`；
- dataset schema：34 findings、5 repair_pairs、`valid=true`。

本轮所有 patch 适配、fixture 与残留路径证据均不进入 strict benchmark，也不改变 34 条 finding 计数。

### 审阅补充：路径和运行时边界

- `paramdict_vuln.cpp` 的原文件名不能直接承接以 `src/paramdict.cpp` 为目标的 patch；临时树 direct path `git apply --check` 预期失败，只有显式映射后的 hunk-compatible 结果可作为适配证据。
- dataset 记录 `direct_artifact_path_applicable=false`，并由 schema 校验该值必须是布尔类型。
- 本地记录尚无“正数组 BIN 输入被修复版接受”的可信 benign 运行样本；因此不能以现有 `c_valid.parambin` 的失败结果充当 B 向验证。BIN length patch 继续保持 `static-regression-only / REVIEW-not-run`。

## 第三十七轮：本地 patch 清单与 BIN fragment 合并证据

### 5 个本地 patch 的证据范围

| 本地材料 | 可重复证据 | 保守结论 |
|---|---|---|
| `PR-6922合并修复.patch` | 当前 `net.cpp` reverse-applicable | 本地快照与合并 patch 后像相容；非本轮运行验证 |
| `PR-text层头校验修复.patch` | reverse-applicable + count-only fixture | 覆盖 TEXT count 上限/符号，不覆盖 same-record token 契约 |
| `PR-blob索引修复.patch` | reverse-applicable + 新增行子集 | 被 PR-6922 吸收的 BIN 子补丁 |
| `PR-paramdict数组len校验修复.patch` | mapped forward application | 仅 BIN array 分支静态 guarded，TEXT 残留 needs-review |
| `PR-YoloDetectionOutput-softmax初始化修复.patch` | local patch summary + reduced fixture | 完整源快照不在本地，`source_proof=false` |

### BIN blob fragment

新增 `repair_evidence.py --container-patch ... --fragment-patch ...`，检查 patch 新增行组成关系：

```text
PR-blob索引修复.patch added lines: 31
contained by PR-6922 merged patch: 31/31
addition_subset: true
```

当前 `TOOLTEST_NCNN/net.cpp` 对该 BIN fragment：

```text
reverse apply: success
BIN unchecked_blob_index candidates:
  postimage: 0
  reverse-patch preimage: 2
```

这是隔离副本中的静态 guard-recognition 对照，不是漏洞准确率、运行时验证或完整语义证明。fragment 也不覆盖 TEXT 守卫和 `top_count` shape-hint 除零处理。

### Yolo 来源边界

Yolo patch 仅有 `src/layer/yolodetectionoutput.cpp` 的单行 `softmax = 0` diff 和 local reduced fixture；本地没有对应完整 source snapshot。因此 repair pair 增加 `local_patch_evidence`，明确 `added_lines=1`、`source_snapshot=not-locally-available`、`source_proof=false`，不执行伪造的 source mapping。

### 回归与边界

- schema 泛化校验所有 `*_fragment` 的对象、patch 路径和适配布尔值；
- schema 校验 local patch 的路径、`source_proof` 布尔值和非负 `added_lines`；
- cwe-repair regression：`PASS`；
- dataset schema：34 findings、5 repair_pairs、`valid=true`；
- strict benchmark、legacy reference、GUARDED 均未改动。

本轮没有新增严格 finding，也没有把 local patch summary 或历史 A/B 描述误作当前 runtime closure。

## 第三十八轮：运行验证预检与 WSL 基础设施归因

### 当前运行环境

本轮先核验是否能实际执行本地 NCNN A/B harness：

- WSL 发行版注册信息仍存在；
- 启动 `Ubuntu-22.04` 时，launcher 返回 `HCS_E_HYPERV_NOT_INSTALLED`；
- 本机未发现 `cl`、`clang++`、`g++`、`cmake`，也未在工作区发现 `net.h` 或 `libncnn`；
- 本地 `loadpoc.cpp` / `loadpoc_file.cpp` 都依赖 `net.h`。

因此当前没有可诚实执行的 WSL 或 native NCNN runtime 路径。本轮未运行 NCNN harness，也没有把已有输入样本当作已验证的运行结果。

### 验证器基础设施归因修复

`cwe_verify.py` 增加 `infrastructure_reason()`：

- `NOBINARY`、超时、子进程异常仍为基础设施错误；
- `HCS_E_HYPERV_NOT_INSTALLED`、`Wsl/Service/CreateInstance` 等 WSL launcher 输出也标为 `wsl-unavailable`；
- 对 Windows launcher UTF-16LE 风格的 NUL 分隔输出进行归一化；
- JSON stdout/stderr 强制 UTF-8 replace，避免 launcher 文本导致 `UnicodeEncodeError`；
- 每个 case 和汇总均输出 `infra_reason` / `infrastructure_reasons`。

使用已有本地输入仅做 launcher preflight（目标为 `/bin/true`，不是 NCNN harness）得到：

```text
malicious_rejected: 0/1
benign_passed: 0/1
infrastructure_failures: 2
infrastructure_reasons: {wsl-unavailable: 2}
verdict: REVIEW
actual_harness_executed: false
```

这证明环境未就绪，而不是任何修复通过或输入被拒绝。该状态已作为 `runtime_preflight_evidence` 写入 PR-6922 repair pair，并由 schema 拒绝“未执行 harness 却为 PASS”的记录。

### 对称性 CLI 可用性

修复 `symmetry_check.py <src_dir> --file net.cpp`：当相对文件名不在当前工作目录时，自动解析为 `<src_dir>/net.cpp`。回归和实际命令均返回：

```json
{"files_scanned": 1, "findings": [], "symmetric": true}
```

### 本轮验收与边界

- cwe-repair regression：`PASS`；
- `cwe_verify.py`、`symmetry_check.py` 编译：`PASS`；
- dataset schema：34 findings、5 repair_pairs、`valid=true`；
- strict benchmark：`16/31`；文件级参考：`20/31`；GUARDED：`3`。

运行环境恢复并具备完整源码、编译依赖、patched harness 与可信 benign 输入之前，所有 NCNN patch 仍只能使用静态/历史记录证据，不升级为当前会话的双向运行闭环。

## 第三十九轮：WSL 恢复后的真实 scoped A/B 验证

### 运行资产与身份

重启并启用 Hyper-V 后，WSL2 `Ubuntu-22.04` 成功启动。确认存在：

- NCNN 源码树，commit `408f6df63c1c6076c0d7294f5fcee55f994d93b5`；
- `loadpoc_verify_baseline` 与 `loadpoc_verify_combined` 双模式 harness；
- 本地 `valid_minimal.parambin`、`text_repeated_bottoms.param`、`F2_neg_topcount.param`、`F1_bottom_oob.param`、BIN 索引样本。

完整机器可读结果写入：

```text
.dsh/skills/cwe-repair/examples/ncnn_pr6922_runtime_evidence.json
```

证据文件同时记录 harness SHA-256，避免只凭文件名认定 before/after 身份。

### BIN 索引范围

使用 combined harness 的 `bin` 模式和本地输入：

```text
恶意 oob_single_idx / oob_top_idx：ret=-1，2/2 rejected
合法 valid_minimal：ret=0，1/1 passed
infrastructure_failures=0
verdict=PASS（仅 BIN 索引测试范围）
```

对应 baseline 对两个索引样本均返回 `ret=0`，形成实际 before/after 差异。该结果支持 PR-6922/PR-blob fragment 的 BIN 守卫范围，但不扩大到所有 NCNN 输入。

### TEXT count 范围

使用 combined harness 的 `text` 模式：

```text
恶意 F2_neg_topcount：ret=-1，1/1 rejected
合法 text_repeated_bottoms：ret=0，1/1 passed
infrastructure_failures=0
verdict=PASS（仅 TEXT count 测试范围）
```

baseline 对 F2 触发 `SIGABRT` / `std::length_error`，合法文本输入仍 `ret=0`。这为 TEXT count 符号/上限守卫提供了本地 runtime A/B，而不是历史报告复述。

### TEXT blob_index residual

combined 对本地 `F1_bottom_oob.param` 仍触发 ASan abort；baseline 也触发 abort。合法文本输入 `text_repeated_bottoms.param` 两侧均 `ret=0`。

因此：

- PR-6922 的 count 守卫在 TEXT F2 范围真实通过；
- `text_blob_index_access` 是独立 residual candidate，不能被 PR-6922 的 BIN index guard 或 TEXT count guard 过滤；
- repair pair 状态是 scoped runtime verified with residual，不是 universal fixed。

### 本轮边界

- 所有运行均使用授权本地 WSL 二进制和预先存在的输入，不连接真实执行器；
- 未运行巨大计数/OOM 样本；
- runtime 证据不新增 strict benchmark 行；
- strict benchmark 仍为 `16/31`，legacy `20/31`，GUARDED `3`；
- dataset 仍为 34 findings、5 repair_pairs、`valid=true`。

## 第四十轮：可发布性导向的历史 PR 闭环执行计划

### 目标

本轮不以抬高旧 strict benchmark 数字为完成条件，而以建立可复核的历史 PR 闭环和可发布证据为条件：

```text
官方 PR/commit -> before/after 源码
-> cwe-repair detect/repair-requirement/symmetry
-> 编译与本地 A/B runtime
-> provenance 与 benchmark v2 分轨记录
```

### 执行阶段与退出条件

1. **官方来源核验**
   - 为至少 3 个 NCNN fix/merge PR 保存官方 URL、PR 编号、base SHA、head SHA 和获取时间；
   - 只有能取得本地源码或明确本地 patch 的材料进入严格回归；其余标为 `external-reference`。
2. **真实 before/after 构建**
   - 在 WSL 隔离目录建立 base/head 源码树或 worktree；
   - 分别运行 detector、repair requirements 和 symmetry；
   - 记录源码 commit、工作树状态、二进制与输入 SHA-256。
3. **双向运行闭环**
   - 每个可运行 PR 至少有一个恶意输入和一个合法输入；
   - 修复版必须恶意拒绝、合法通过、基础设施失败为 0；
   - 任何 residual 单独记录，不用局部 PASS 代表全路径修复。
4. **同类型 Git 经验转化**
   - 只选择 2-3 个与 NCNN 边界/对称路径同构的 AimRT、AgiBot 或 MindSpore PR；
   - 每条经验必须落成 detector 规则、fixture、symmetry 检查或 regression；仅有阅读记录不计为改进。
5. **benchmark v2**
   - 增加 `preimage_detection`、`postimage_guard`、`runtime_rejection`、`runtime_benign`、`provenance` 五个独立维度；
   - 保留旧 `16/31` 作为兼容基线，不将 repair pair、external-reference 或 runtime PASS 混入旧 strict numerator。

### 发布门槛

- 至少 3 个真实 NCNN PR 完成来源核验；
- 至少 2 个 PR 完成真实 before/after detector + runtime 闭环；
- 所有 verified 结果可追溯到 commit、命令、输入和二进制哈希；
- 基础设施失败不能生成 PASS；
- residual、未取得源码和仅外部描述材料均显式标记；
- regression、schema、symmetry 和 benchmark v2 检查全部通过。

## 第四十一轮：官方 PR 物化、跨项目经验转化与 benchmark v2

### 官方 NCNN 来源核验

通过 GitHub 官方 API/远程 `upstream=https://github.com/Tencent/ncnn.git` 核验并按 base/head SHA 获取了以下材料：

| PR | 官方状态 | base | head | 真实改动范围 |
|---|---|---|---|---|
| [#6383](https://github.com/Tencent/ncnn/pull/6383) | merged | `5154f22a4c146959beda380dc7522de53704d940` | `1d6c7f55d11aee7d9808802ff913f8482f8e2ac7` | `src/net.cpp` parser failure cleanup/explicit return |
| [#6337](https://github.com/Tencent/ncnn/pull/6337) | merged | `00f816ffd52d306c00c38b4dbbd3a5b089f73612` | `b0d970b0e3a2a23e011aeddd682063e0ad8e7a8b` | `src/paramdict.cpp` quoted-token consumption + test |
| [#2213](https://github.com/Tencent/ncnn/pull/2213) | merged | `5a91a640cbf96c8a14df0c637542215e9666f1e1` | `cdfcc49d9cb1f4829a3c77feda266d6b325e9f29` | `src/layer/packing.cpp` size_t offset arithmetic |
| [#6922](https://github.com/Tencent/ncnn/pull/6922) | **open / unmerged** | `946fe3fb14a8dff8c06df763f67be522167b2f00` | `408f6df63c1c6076c0d7294f5fcee55f994d93b5` | `src/net.cpp` count/index/shape-hint guards |

每个已合并 PR 都建立了独立的 WSL detached worktree；#6922 另作为 `official-local-materialized-upstream-open` 保存，`strict_eligible=false`。官方 open PR 不被表述为上游已发布修复。

### cwe-repair before/after 对照

新增规则和跨挂载路径支持后，真实官方源码得到：

```text
#6383 parser_error_continue: before 6 个入口分支，after 0
#6337 paramdict_terminal_quote_rescan: before 1，after 0
#2213 pointer_offset_int_multiply: before 5，after 0
#6922 unchecked_parser_count: before 命中，after 清零
#6922 divide_by_input: before 命中，after 清零
#6922 BIN index: before 命中，after BIN 范围清零；TEXT 路径 residual 保留
```

Windows `cwe_detect.py` 新增 WSL UNC 路径显示处理，避免 `os.path.relpath()` 跨盘抛出异常。检测结果按稳定路径和行号保存，不把全文件噪声当成 PR 命中。

### 真实构建与运行证据

- #6337 base/head 均独立编译并运行官方 `test_paramdict`；新增 quote-contract harness：
  - base：`ret=0` 但丢失后续 key，harness 失败；
  - head：`quote_contract=PASS`。
- #2213 base/head 均独立编译并运行官方 `test_packing`；新增 shape-only `cstep` harness：
  - base：`cstep=18446744073709551614`，期望 `4294967294`，失败；
  - head：`cstep_contract=PASS`。
  - harness 不分配大矩阵，不执行资源消耗型输入。
- #6922 base/head 均独立编译 `loadpoc_verify`：
  - BIN：base 恶意索引 `0/2` 拒绝，head `2/2` 拒绝；合法输入两侧 `1/1` 通过；
  - TEXT count：base `0/1` 拒绝并出现 `SIGABRT`，head `1/1` 明确 `ret=-1`；合法输入两侧 `1/1` 通过；
  - 基础设施失败均为 `0`。
- #6383 已完成独立构建和静态闭环，但当前最小 malformed 参数没有进入 `pdlr/lr` 失败分支，runtime 保持 `REVIEW`，没有伪造 PASS。

完整 v2 数据在 `.dsh/skills/cwe-repair/examples/ncnn_history_benchmark_v2.json`；已有 #6922 scoped runtime 细节仍在 `ncnn_pr6922_runtime_evidence.json`。

### 跨项目 Git 经验的实际转化

只纳入能由官方 PR/review 核对并转成代码资产的经验：

- [ONNX Runtime #28003](https://github.com/microsoft/onnxruntime/pull/28003)：乘法必须在 checked arithmetic 后再窄化；合法 zero extent 要保留定义行为。转成 `unchecked_shape_product_narrow`、`zero_extent_offset`，并新增 `shape_arithmetic_before.cpp/after.cpp` 与回归。
- [ONNX Runtime #23435](https://github.com/microsoft/onnxruntime/pull/23435)：部分初始化失败后，cleanup、状态位和后续 callback/运行入口必须共同受保护。该经验记录为下一轮 `partial_init_cleanup` needs-review 规则候选，尚未把它虚报为已实现能力。
- [ONNX Runtime #28112](https://github.com/microsoft/onnxruntime/pull/28112)：外部 `size_t` 先做类型上限检查，再转换到 `int32_t`；不依赖 throwing narrow 作为 API 控制流。保留为后续 `validated_narrowing` 设计依据。

没有找到能在本轮官方页面上直接核对的 AimRT/MindSpore 同主题成熟 PR，因此未编造案例，也未将它们写成已吸收经验。

### benchmark v2 结果与边界

`benchmark_v2.py` 独立输出五个维度：`preimage_detection`、`postimage_guard`（含 `GUARDED_SCOPED`）、`runtime_rejection`、`runtime_benign`、`provenance`。当前 6 个 case 的结果为：

```text
preimage HIT: 6/6
postimage GUARDED: 5/6
postimage GUARDED_SCOPED: 1/6
runtime rejection PASS: 2/6（其余 NOT_APPLICABLE/REVIEW）
runtime benign PASS: 5/6
provenance complete: 6/6
strict eligible v2 cases: 3（仅已合并 PR）
legacy_benchmark_untouched: true
```

`#6922` BIN case 的 `GUARDED_SCOPED` 明确说明：BIN 入口已守卫，但独立 TEXT `blob_index` residual 仍在；这不是全文件 fixed。旧 leaderboard 仍保持 `16/31`，没有把 v2、repair pair、open PR 或 runtime PASS 混入旧 strict numerator。

## 第四十二轮：补齐 #6383 failure-path 与 #6922 TEXT residual

### #6383 真实 failure-path fixture

此前 fixture `Input input 0 1 999999=1` 把非法参数当成了 top blob 名称，未进入 `ParamDict::load_param`。新增 `.dsh/skills/cwe-repair/examples/ncnn_pr6383_layer_param_failure.txt`：

```text
7767517
1 1
Input input 0 1 out 999999=1
```

在同一 harness、同一合法输入和官方 fresh base/head 构建上，`cwe_verify --asan` 结果为：

```text
#6383 base: malicious 0/1, SIGSEGV; benign 1/1
#6383 head: malicious 1/1, ret=-1; benign 1/1; infrastructure failures 0
```

因此 #6383 现在具备真实 runtime 对照，但 base 的崩溃仍按失败处理，只有 head 侧可称拒绝 PASS。

### #6922 TEXT residual 对照

官方 open PR #6922 的 `TEXT load_param` 仍有 `d->blobs[bottom_blob_index]` 路径未守卫。`F1_bottom_oob.param` 在 fresh 官方 base/head 上均得到：

```text
malicious 0/1, SIGSEGV; benign 1/1
```

这与 detector 的 `text_blob_index_access` residual 对齐，说明 head 的 BIN index guard 不覆盖 TEXT parser。v2 新增 `NCNN-PR-6922-TEXT-BLOB-RESIDUAL`，明确记录为 `postimage_guard=MISS`、runtime `REVIEW`，不计入 strict。

### 更新后的 v2 汇总

```text
cases: 7
preimage HIT: 7/7
postimage GUARDED: 5/7
postimage GUARDED_SCOPED: 1/7
postimage MISS: 1/7
runtime rejection PASS: 2/7
runtime benign PASS: 6/7
provenance complete: 7/7
strict eligible v2 cases: 3
legacy_benchmark_untouched: true
```

#23435 的 `partial_init_cleanup` 已从候选转为 needs-review detector + before/after fixture；它仍不自动证明任意真实组件语义正确。所有新增证据保存在 `ncnn_official_pr_runtime_evidence.json`，legacy leaderboard 继续保持 `16/31`。

## 第四十三轮：契约驱动自动修复与局部语义判定

### 自动修复层升级

新增 `repair_contract.py` 与 `repair_plan.py`，将修复从“命中规则后直接生成通用片段”升级为契约门禁：

```text
AUTO_CANDIDATE -> 生成候选 unified patch，但默认不允许自动应用
REVIEW         -> 缺少容量、返回值、清理或零值语义，禁止生成自动候选
REFUSE         -> 目标行/参数/契约不匹配，拒绝修复
NO_CHANGE      -> 目标访问前已有完整守卫，不重复修改
```

对 parser-owned partial state，必须显式提供 cleanup；对跨 WSL UNC 路径生成稳定 repo-relative patch；对已有下限/上限守卫的访问返回 `NO_CHANGE`。`cwe_repair.py` 也支持把 cleanup 写入 CWE-125/787 候选 patch。

### 全路径门禁

新增 `repair_verdict.py`，只有以下五类证据全部通过才输出 `SEMANTIC_VERIFIED`：

```text
before target hit
-> after target residual clear
-> text/bin 或成对入口 symmetry pass
-> malicious 全拒 + benign 全过 + infrastructure failures=0
-> base/head 或 local-only provenance 完整
```

该状态的证明范围固定为 `named-local-contract-path`，`formal_proof=false`。它是局部语义契约的证据闭环，不声称对任意程序状态空间完成形式化证明。

### #6922 local-only 实证

基于官方 open PR #6922 head `408f6df...` 创建隔离 local-only worktree，契约门禁通过后对 TEXT parser 三个访问点增加范围检查和 parser state cleanup：

```text
text_blob_index_access: 2 -> 0
unchecked_blob_index: 1 -> 0
symmetry: symmetric=true
runtime: malicious 1/1 rejected, benign 1/1 passed, infrastructure=0
repair_verdict: SEMANTIC_VERIFIED
```

证据保存在 `ncnn_pr6922_local_text_fix_evidence.json`、`ncnn_pr6922_local_text_fix_symmetry.json` 和 `ncnn_pr6922_text_local_fix.patch`。该修复来源仍标记 `local-only`，不修改官方 open PR，也不进入 legacy strict benchmark。

当前 v2 为 8 cases：preimage `8/8`、postimage `GUARDED 6/8`、`GUARDED_SCOPED 1/8`、`MISS 1/8`、runtime rejection `4/8`、benign `8/8`、provenance `8/8`；strict eligible 仍只有 3 个已合并官方 PR，legacy leaderboard 仍为 `16/31`。

## 第四十四轮：成对入口契约矩阵与全路径门禁

新增 `contract_matrix.py`，把 text/bin、CPU/Vulkan 等成对入口抽象为显式路径矩阵。每条声明路径必须同时具备：源码存在、目标 residual 清零、守卫/清理 marker 完整、恶意输入全拒、合法输入全过、基础设施失败为 0。矩阵缺少任一 required path 时强制返回 `REVIEW`。

当前 #6922 local-only TEXT 修复的矩阵：

```text
contract: blob-index-range-and-error-cleanup
text-load-param: PASS, residual=0, runtime 1/1 + 1/1
bin-load-param: PASS, residual=0, runtime 2/2 + 1/1
matrix: MATRIX_VERIFIED
repair_verdict: SEMANTIC_VERIFIED
```

矩阵定义保存在 `.dsh/skills/cwe-repair/examples/ncnn_pr6922_local_text_bin_contract_matrix.json`，并已接入 `repair_verdict.py` 的 `paired_path_matrix` 硬门禁。若删去 BIN 路径，回归会得到 `REVIEW`，避免单一路径 PASS 被错误推广为全路径正确。

本轮仍保持 `formal_proof=false`。当前证明范围是声明的成对本地路径和命名安全契约，不覆盖未声明入口、任意外部状态或完整程序状态空间；不能证明的路径必须继续降级为 `REVIEW`。

## 第四十五轮：扩展全过程验证案例库

### 数据集局限性判断

原始 `embodied-ai-cwe-dataset.json` 的 34 条 finding、5 个 repair pair 适合验证原型是否能完成单案例检测/修复/验证闭环，但不适合直接支撑跨组件、跨路径的泛化结论，主要限制为：

```text
组件集中：NCNN 占主导，AimRT/AgiBot/MindSpore 的 PR 修复过程不足
修复集中：边界、计数、解析器路径较多，生命周期、异步、设备后端不足
证据集中：部分是源码/本地 fixture，只有少数同时具备 official base/head、build、runtime 和 provenance
路径集中：TEXT/BIN 已开始矩阵化，但 CPU/Vulkan、同步/异步、配置/默认入口仍不充分
```

因此扩展时不能只追求 finding 数量。应同时报告四个分母：

1. `finding_count`：检测到的问题数量；
2. `pr_case_count`：有官方 PR 或本地修复来源的案例数量；
3. `locally_materialized_count`：有可定位源码和 base/head 的案例数量；
4. `semantic_verified_count`：通过 contract、matrix、build、双向 runtime 和 provenance 全门禁的案例数量。

### PR registry

新增 `.dsh/skills/cwe-repair/scripts/pr_case_registry.py` 和 `.dsh/skills/cwe-repair/examples/embodied_ai_pr_case_registry.json`。当前 registry 收录 10 个案例：

```text
official-local-materialized:             3
official-local-materialized-upstream-open: 1
local-only:                              1
external-reference:                      5
```

按项目分布：Tencent/ncnn 5、microsoft/onnxruntime 3、mindspore-ai/mindspore 2。只有 5 个案例具备本地 provenance；其中 3 个是已合并官方 NCNN PR，1 个是官方 open PR 的物化快照，1 个是明确标为 `local-only` 的防御性实验。5 个 external-reference 只用于方法比较和候选 contract 设计，不计入本地 verified，也不改变 legacy strict benchmark。

候选源中暂未找到同时具备可核验官方 PR 页面、before/after provenance 和本地验证资产的 AimRT/AgiBot 修复案例，因此只记录为 `candidate_sources.unconfirmed`，不把仓库级源码发现冒充 PR 修复证据。

### 纳入/排除标准

纳入：官方 PR/commit URL 可追溯；项目与 AI 推理、模型解析、机器人中间件、控制输入或设备后端有关；存在可描述的安全 contract；能够记录修复前后状态和缺失证据。

排除：只有二手博客没有官方来源；只有漏洞描述没有修复前后差异；无法区分上游修复与本地实验；需要真实机器人、联网服务或利用链才能验证；会引入 OOM/资源耗尽样本而无法在受控本地环境中安全执行。

该 registry 与旧 34-finding 数据集分离，验证命令已加入 `test_cwe_repair.py`。registry schema 通过，legacy leaderboard 仍保持 strict `16/31`、legacy `20/31`、guarded `3`。

## 第四十六轮：证据就绪度与物化队列

新增 `pr_case_readiness.py`，把每个 PR 案例拆成 8 个独立门禁：

```text
official_source, base_head, source_pair, detect,
repair_plan, symmetry, runtime, provenance
```

输出不是单一“可信/不可信”标签，而是 `readiness_score`、缺口 `gaps`、优先级 `priority` 和下一步动作。当前 10 个 registry 案例的队列为：

```text
ready-for-semantic-verification: 4
complete-missing-gates:          1
materialize-external-reference:  5
```

external-reference 的官方 PR 标题或 review 描述不会自动计入本地 detect/runtime；缺少 base/head、源码或 runtime 时，评分器会明确列出缺口。

新增 `pr_materialization_plan.py` 和 `embodied_ai_pr_materialization_plan.json`，第一批物化对象为：

```text
ORT-PR-28003: shape arithmetic / integer overflow
MS-PR-70694: dynamic-shape overflow regression
```

选择标准是：已有明确官方来源、契约与现有 CWE-190/shape fixture 相关、可以使用小尺寸边界输入完成防御性验证。计划明确禁止 OOM、超大分配、网络目标、真实执行器和利用链；任何缺失证据都保持 `REVIEW`。

该流程将案例采集从“收集 PR 链接”推进为：

```text
official reference
-> registry
-> evidence readiness
-> safe materialization plan
-> detect/repair-plan/symmetry/matrix
-> build/runtime/provenance
-> semantic verdict
```

## 第四十七轮：ORT-PR-28003 物化与 bounded arithmetic 验证

通过 GitHub API 固定 ORT PR #28003：

```text
state: closed/merged
base: 0fedb26c93e6c29882185715d5c2bb583a6d92b5
head: 795675a77ebb898302c5798bd6247658db165d14
merge: ffbc5e8d8223c44e3ca0d9a197e0193bdff03af0
changed files: 4
```

changed scope 为 `safeint.h`、CPU RNN `rnn.cc` 和两个测试文件。两个 exact revision 已通过 blob-filter/sparse worktree 物化。静态 detector 结果：base RNN `13 raw / 10 merged` CWE-190 findings，head `7 raw / 4 merged`；目标 `SafeMul`、`narrow` 和 zero-extent markers 均存在。head 仍保留 Y_h/frame offset sibling arithmetic residual，已在 `ort_pr28003_contract_matrix.json` 中显式声明为 scoped residual，不能被静默清零。

从官方 diff 提取的 reduced arithmetic fixture 在 ASan/UBSan 下完成双向验证：负 shape 与乘法溢出边界 `2/2` 拒绝，合法小 shape `1/1` 通过，基础设施失败 `0`。证据保存于 `ort_pr28003_bounded_runtime_evidence.json`，binary 和 fixture hash 均已记录。

该结果仍不是完整 ORT RNN operator 证明：完整 ORT test target、其他 execution provider 和 full runtime 尚未执行，因此 ORT readiness 保持 `6/8`，缺口为 symmetry/full runtime，状态为 `REVIEW`。

## 第四十八轮：MS-PR-70694 provenance 纠错

通过 Gitee API 固定 MindSpore PR !70694：

```text
state: merged
base: 2de6095d1b53692e327eb074426b5ad2c29e66ba
head: 7493f8535900c238ca0ebe0273cacac3aae4f7f7
merged: 2024-06-13T14:31:57+08:00
```

但 exact head commit message 是 `test dump sample bugfix`，compare diff 只有 `tests/st/dump/test_dump_sample.py`，与 PR 标题“动态 shape 溢出检测用例”及预期 CWE-190 contract 不一致。两个 exact worktree 已建立并只保留该 changed file；案例标记为 `contract-mismatch-review`，证据保存于 `ms_pr70694_diff_review.json`。

这条记录的研究价值在于验证了全过程组件必须检查“标题/描述 → exact revision → changed scope → contract”一致性。该案例不能进入 dynamic-shape detector、repair-plan 或 runtime 验证，readiness 为 `4/8`，缺口为 detect、repair_plan、symmetry、runtime，保持 `REVIEW`。

同时修正 `pr_case_readiness.py` 的状态解析：provenance 文件名包含 `review` 不再被误判为缺证据；`not-applicable`、`not-run`、`contract-mismatch` 则明确计为失败状态。完整回归已覆盖这一负例。

## 第四十九轮：ORT QNN 生命周期契约物化

继续扩展 registry：ORT-PR-23435 的官方元数据固定为 merged，base `3e4c5e64877c6d9814e4ebce5dcbb1fe71588ec5`、head `81573cce5bec34dc7bdf6883ef96f0c30dffcdca`，changed file 为 `onnxruntime/core/providers/qnn/builder/qnn_backend_manager.cc`。exact base/head 已物化。

官方 diff 的契约是 QNN 初始化失败后的生命周期守卫：logger 默认实例检查、`backend_setup_completed_` 守卫（HTP power/RPC latency）、释放资源路径的错误信息。base/head 的 `iterator_end_deref` 命中是带守卫的低置信非目标误报，不作为该 PR 的目标契约。

由于本地没有 QNN 硬件/专有 backend，该案例保持 `REVIEW`。当前 queue 为：

```text
ready-for-semantic-verification: 4
complete-missing-gates:          4
materialize-external-reference:  2
```

registry 汇总为 `official-local-materialized 6`、`official-local-materialized-upstream-open 1`、`local-only 1`、`external-reference 2`。legacy 34-finding 数据集和 strict leaderboard 未改变。

下一轮将优先处理剩余 external-reference 案例（ORT-PR-28112、MS-PR-89363）的 exact provenance 与 contract 一致性；同时保留 ORT 完整 RNN test target 的构建基础设施缺口记录。

## 第五十轮：ORT-28112 与 MindSpore-89363 物化

### ORT-PR-28112

通过 GitHub API 固定：

```text
base:  a208df8a25a53d1a6c3334487e58574a839460f5
head:  066e6c085c63bfb16460d663333646da698ec6fd
merge: 564cabfc98a5cd1367b22be590fb44141a27370b
```

changed scope 为 5 个文件，核心修复在 `onnxruntime/core/session/utils.cc`：

```text
base: static_cast<int>(model_data_length) 2 次
head: INT32_MAX 检查 + narrow<int32_t>，目标命中 0 次
```

现有 detector 原先漏报 `static_cast<int>(...)` 窄化；新增 `static_cast_narrow_truncation` 规则后，ORT-28112 目标模式完成 `2 -> 0` 静态闭环。该规则只针对长度/尺寸语义变量，避免把普通安全转换全部报告为问题。

官方 git transport 在本轮不可用，因此通过官方 GitHub contents API 按 exact SHA 物化 base/head changed files，方法和 hash/provenance 保存在 `ort_pr28112_provenance.json`。contract matrix 的 marker 全部通过、target residual 为 0，但完整 ORT session-load runtime 尚未执行，矩阵和案例状态均为 `REVIEW`。

### MS-PR-89363

通过 Gitee API 固定：

```text
base: 14ce9eac501d3db833bd5d4db1863c36035d2bd8
head: 4450b28f2569313f95cb71728f8f417632dd3d78
```

核心 changed files 的官方 diff 显示：

```text
buffer_get_cpu_kernel.h:
  SIZE_MAX / one_exp_len 溢出检查
  index_size * one_exp_len 与 inputs[i]->size() 范围检查

cpu_hash_table_util.h:
  int32_t value_size -> size_t
  每个 dim 乘法前执行 SIZE_MAX / dim 检查
```

`ms_pr89363_contract_matrix.json` 将 detector 对 guarded multiply 的 residual 显式列为 scoped residual，所有目标 marker 通过；由于 MindSpore 完整 kernel build/runtime 未执行，最终保持 `REVIEW`。证据保存在 `ms_pr89363_provenance.json`。

### 队列变化

两个案例均从 external-reference 升级为 `official-local-materialized`，但没有升级为 verified：

```text
ready-for-semantic-verification: 4
complete-missing-gates:          6
materialize-external-reference:  0
```

这轮还扩展了 detector 对 `static_cast<int>` 长度窄化的覆盖，并增加 zero-count registry/readiness 的稳健回归。legacy 数据集、strict benchmark 和所有历史计数保持不变。

## 第五十一轮：两个物化案例的 reduced 双向验证

为避免“full framework build 不可用”导致局部 contract 完全没有 runtime 证据，新增两个严格受控的 reduced harness；它们不加载模型、不启动真实执行器、不分配大对象，且不改变 full-case 状态。

### ORT-PR-28112 reduced contract

`INT32_MAX + 1` 输入被拒绝，`INT32_MAX` 合法边界通过：

```text
malicious: 1/1 rejected
benign:    1/1 passed
ASan/UBSan: enabled
infrastructure failures: 0
```

证据：`ort_pr28112_bounded_runtime_evidence.json`。full ORT session-load path 仍为 `REVIEW`。

### MS-PR-89363 reduced contract

覆盖 `index_size * one_exp_len` 溢出、offset 超出 input size、以及合法小尺寸：

```text
malicious: 2/2 rejected
benign:    1/1 passed
ASan/UBSan: enabled
infrastructure failures: 0
```

证据：`ms_pr89363_bounded_runtime_evidence.json`。full MindSpore CPU kernel/runtime 仍为 `REVIEW`。

这两条 reduced PASS 只提升局部 contract 的证据强度，不改变 readiness 的 full gate：两个案例仍因未完成完整 symmetry/full runtime 而处于 `complete-missing-gates`，不能进入 strict 或 `SEMANTIC_VERIFIED`。

## 第五十二轮：证据等级格接入 readiness

自然语言 runtime 字段容易把“reduced PASS”“目标路径 PASS”和“完整组件 PASS”混在一起。本轮新增 `evidence_lattice.py`，对每个案例输出独立的 `gate_status`、`required_gates`、`evidence_level`、`full_gate_ready` 和 `formal_proof=false`。

证据等级固定为：

```text
FULL_GATED_LOCAL  # 所有 required gates 均 verified
SCOPED_RUNTIME    # 有本地 source pair，且存在明确 scoped/reduced runtime
LOCAL_STATIC      # 有本地 source pair，但没有完整 runtime gate
MATERIALIZED_REFERENCE
REFERENCE_ONLY
```

当前 10 个案例的结构化分布为：

```text
FULL_GATED_LOCAL: 4
SCOPED_RUNTIME:  4
LOCAL_STATIC:    2
```

其中 ORT-28112 和 MS-89363 的 reduced runtime 分别为 `1/1 + 1/1`、`2/2 + 1/1`，但 `full_gate_ready=false`；QNN 案例和 contract-mismatch 案例的 runtime 为 `missing`。旧的 8-gate readiness 布尔结果保持兼容，strict eligibility 规则未被 lattice 放宽。

同时修正 MS-PR-89363 的 upstream state 为 `merged`，与 Gitee exact API provenance 一致。新增 lattice 单元回归覆盖 `MATRIX_VERIFIED`、`not-run`、`not-applicable` 和 scoped REVIEW 混合状态，避免状态解析误升级。

## 第五十三轮：MindSpore-90617 shape-axis 契约物化

从 MindSpore 官方 PR 列表筛选到 `MS-PR-90617`：标题为 `r2.7.2 fix cumsum grad shape out-of-range access`，compare 只有两个 changed files：`mindspore/ops/grad/grad_math_ops.cc` 与 `tests/st/mint/test_cumsum.py`。exact provenance 为：

```text
base: 948c239b1ffdb8252661d9b7fda5bd377f4fef1e
head: 5eb07997f04ee807a59a1e209d68a7c4d0daef74
merged: 2025-11-20T09:08:18+08:00
```

官方 diff 与契约完全一致：在 `CumsumExt` backward path 中先检查 `-rank <= dim <= rank - 1`，再把负轴归一化后访问 `x_shape[dim_value]`；测试同时新增合法 `dim=-2` 路径。新增 `shape_axis_index` detector 规则覆盖此前漏报的 shape/axis 标量索引。head 中目标访问仍会被通用规则命中，但 `ms_pr90617_contract_matrix.json` 将目标行和既有 `axis_value` residual 显式列为 allowed scoped residual，并要求 rank/归一化 markers 全部存在。

reduced harness 结果：非法高轴、非法低轴共 `2/2` 拒绝；合法负轴和零轴共 `2/2` 通过；ASan/UBSan 开启，基础设施失败为 0。full MindSpore graph/runtime 尚未执行，因此案例保持 `REVIEW`、`SCOPED_RUNTIME`，不进入 strict 或 `SEMANTIC_VERIFIED`。

registry 现在为 11 cases，项目分布为 NCNN 5、ONNX Runtime 3、MindSpore 3；evidence lattice 分布为 `FULL_GATED_LOCAL 4`、`SCOPED_RUNTIME 5`、`LOCAL_STATIC 2`。legacy 数据集和 leaderboard 继续不变。

## 第五十四轮：候选筛选的范围拒绝规则

检查 MindSpore `MS-PR-90890`（`[BUGFIX]Fix std::accumulate overflow`）时，官方标题和第一个 commit message 与 arithmetic 契约一致，但 exact compare 返回至少 200 个 changed files，涉及 CPU/GPU/Ascend 多后端的大规模 shape/type 迁移；PR 还包含第二个 `Fix Tensor invalid args check` commit。该案例写入 `ms_pr90890_screening.json` 并进入 `candidate_sources`，状态为 `screened-defer-broad-scope`，不进入 11-case registry，不伪造单路径 evidence。这个筛选规则防止“标题匹配”替代可审计的 source scope。

## 第五十五轮：MindSpore-91146 非负 shape 双路径契约

继续筛选官方 PR，`MS-PR-91146` 只有 3 个 changed files，且 title/diff/test 完全一致：`empty.cc` 在 tensor 创建前逐维拒绝负 shape，`ones.cc` 在 shape inference 中逐维拒绝负 shape，测试覆盖 `randn/rand/randint` 的负维错误路径。

exact provenance：

```text
base: 538ff34fbc1eaa00355d5a2fb5ed1b17a76ecc4e
head: 4c2308c95c7f1584e18aedb01ca3b90fb7a67168
merged: 2025-12-16T14:22:51+08:00
```

`ms_pr91146_contract_matrix.json` 覆盖 empty/ones 两个 declared paths，required markers 全部存在；ones 的低置信 `shape[i]` residual 被限定在允许行。reduced harness 对负 shape `2/2` 拒绝，对零/正 shape `2/2` 通过，ASan/UBSan 开启且基础设施失败为 0。由于没有运行完整 MindSpore executor，matrix 保持 `REVIEW`，案例 evidence level 为 `SCOPED_RUNTIME`，readiness 仅缺 runtime gate。

registry 现在为 12 cases：NCNN 5、ONNX Runtime 3、MindSpore 4；物化分类为 official-local-materialized 10、official-local-materialized-upstream-open 1、local-only 1。evidence lattice 分布为：

```text
FULL_GATED_LOCAL: 4
SCOPED_RUNTIME:  6
LOCAL_STATIC:    2
```

legacy 34 findings、5 repair pairs、strict `16/31`、legacy `20/31` 和 guarded `3` 均未改变。

## 第五十六轮：ORT-28003 构建入口与 CMake blocker 精化

本轮在 ORT head exact commit 上创建独立 `pr28003_build_probe`，从本地 partial-clone object store 补齐 `build.sh`、`tools/ci_build`、`tools/python`、`cmake` 以及目标 changed files。`tools/ci_build/build.py --help` 成功，说明构建入口和 Python 参数层可用。

随后运行受控 `--update` configure probe，参数为 `--skip_submodule_sync --skip_pip_install --skip_tests --allow_running_as_root`，没有编译、测试、executor 或网络目标执行。probe 已进入 CMake，但 exact revision 要求 CMake `>=3.28`，当前 Ubuntu 环境为 `3.22.1`，因此在 configure 前置检查处停止。该结果更新到 `ort_pr28003_build_feasibility.json`：blocker 从“入口缺失”精化为“CMake 版本不足 + 完整 dependency/source graph 尚未 provisioned”。ORT-28003 full runtime 仍为 `REVIEW`，reduced SafeInt/RNN PASS 不升格。

## 第五十七轮：ORT-28003 full pinned configure/build 通过

本轮发现用户级 CMake `/home/kaltsit/.local/bin/cmake` 为 `3.31.10`，并利用本地 `/tmp/deps_mirror` 补齐 exact `deps.txt` 中缺失的三个 archive。cpuinfo、GSL、ONNX 的 SHA1 分别为：

```text
30b2a07fe4bae8574f89176e56274cacdd6d135b
cf368104cd22a87b4dd0c80228919bb2df3e2a14
321d4acc807c8e0fb0bbcc0424a143dffde1e846
```

在 exact head `795675a77ebb898302c5798bd6247658db165d14` 创建独立 `pr28003_full_probe`，物化约 504MB 的 pinned `onnxruntime`、`include`、`cmake`、build helpers 与测试源；base `0fedb26c93e6c29882185715d5c2bb583a6d92b5` 也完成同 scope configure。head configure PASS，且 `onnxruntime_provider_test` 的 generated `DependInfo.cmake` 明确包含 `rnn_op_test.cc`。

head target-only build 使用 `-j2`，不执行测试、executor 或 network target，最终 `Built target onnxruntime_provider_test`，二进制大小约 1.1G，SHA256 为 `ec1bfff81a5e4f85419483f9a3efa6a323df3404ceb7b92d8bd7c808c4d1b952`。这闭合 ORT-28003 的 full configure/build gate，但没有闭合 runtime gate；案例继续为 `REVIEW`，reduced harness 仍只是 `SCOPED_RUNTIME`。

同时将 contract matrix 的 `runtime` 与 `scoped_runtime` 分离：full runtime 使用 `0/0 + REVIEW`，bounded evidence 使用独立 `2/2 + 1/1 PASS`。新增回归确保带 `reduced/scoped/bounded` 标记的 PASS 永远不会被识别为 full 或 `MATRIX_VERIFIED`。

## 第五十八轮：组件级函数路径盘点

为避免“编译了完整 target”被误写成“验证了完整路径”，新增 `ort_pr28003_path_inventory.json`。该 artifact 把两个 declared contract paths 绑定到 `RNN<float>::Compute` 的具体行和 marker，并单独列出 `Assign_Y_h`、`ClearMissingFrames` 以及已编译但未执行的 RNN tests。

组件现在可以机器可读地区分：

```text
declared contract paths: 2
full runtime:             NOT_RUN
scoped runtime:           PASS
formal all-path proof:    unverified
```

inventory 同时列出 base/head paired runtime、全 provider/config 组合、full ASan/UBSan execution、未声明 caller/error paths 和形式化证明等缺口。这样 readiness 不再只给出一个总分，而能指出具体未覆盖维度；ORT-28003 仍保持 `REVIEW`，legacy benchmark 不变。

## 第五十九轮：2026-08-25 组件进展与今日任务收束

### 今日任务目标

今天的目标不是让模型生成更多结论，而是继续把 `cwe-repair` 组件改进为面向具身智能 AI runtime 的可审计全路径语义验证组件：优先推进 ORT-PR-28003 的 exact base/head、source scope、CWE-190 contract、matrix、build/runtime evidence；同时对 MS-PR-70694 保持严格 provenance 与契约不匹配审查。所有缺证据案例必须保持 `REVIEW`，不得修改 legacy strict benchmark，不生成利用链、不使用 OOM/超大输入、不运行真实 executor 或网络目标。

### 今日对组件的实际改进

1. **构建证据从“环境 blocker”推进到可复现的 pinned build gate。** 找到用户级 CMake `3.31.10`，用本地 `/tmp/deps_mirror` 补齐并 SHA1 校验 cpuinfo、GSL、ONNX exact archives；在 ORT exact head `795675a77ebb898302c5798bd6247658db165d14` 的独立 full probe 中完成 configure。
2. **head target build 已通过。** `onnxruntime_provider_test` 成功链接，generated manifest 包含 `rnn_op_test.cc`，`rnn.cc` 已实际编译；binary SHA256 为 `ec1bfff81a5e4f85419483f9a3efa6a323df3404ceb7b92d8bd7c808c4d1b952`。这使组件能够区分 `configure=PASS`、`build=PASS` 与 `runtime=NOT_RUN`，而不是把编译成功当作语义正确。
3. **full/scoped runtime 已结构化分离。** `contract_matrix.py` 新增 `runtime` 与 `scoped_runtime` 字段；带 `reduced/scoped/bounded` 标记的 PASS 永远不能满足 full runtime 或 `MATRIX_VERIFIED`，`0/0` 也不能成为伪 PASS。ORT-28112、MS-89363、MS-90617、MS-91146 均已接入该 schema并通过回归。
4. **路径覆盖由总分推进到函数级 inventory。** 新增 `ort_pr28003_path_inventory.json`，把两个 declared contract paths 绑定到 `RNN<float>::Compute` 的函数与行，单列 `Assign_Y_h`、`ClearMissingFrames` 和已编译但未执行的 RNN tests，并明确列出未覆盖的 caller/provider/config/runtime/formal-proof 维度。
5. **组件回归和证据审计保持稳定。** `cwe-repair regression: PASS`；12-case registry、evidence lattice anomaly audit、legacy dataset/leaderboard均保持不变。

### 今日验证结果

```text
registry:              12 cases
FULL_GATED_LOCAL:       4
SCOPED_RUNTIME:         6
LOCAL_STATIC:            2
lattice anomalies:      0
legacy dataset:         34 findings / 5 repair_pairs
leaderboard:            strict 16/31; legacy 20/31; guarded 3
```

### 今日未完成项与准确边界

- ORT base exact revision `0fedb26c93e6c29882185715d5c2bb583a6d92b5` 已完成同配置 configure，但 `onnxruntime_provider_test` 的 paired base build 在约 63% 处因今日收工被主动中断；不能写成 base build PASS，也不能宣称 before/after build symmetry 已闭合。
- ORT full provider/executor runtime 没有运行；reduced harness 仍为 `SCOPED_RUNTIME`，ORT-28003 继续 `REVIEW`。
- MS-PR-70694 exact diff 仍与 dynamic-shape overflow contract 不匹配，继续 `REVIEW`，不执行错误契约验证。
- 当前组件仍不是形式化证明器，`formal_proof=false`；全路径语义证明还缺 sound 的全程序路径覆盖、跨配置/跨 provider 组合和允许边界内的 full runtime 证据。

### 明日续接点

1. 从 `pr28003_full_base_probe/build_configure` 恢复 `onnxruntime_provider_test` target-only build，记录 base binary hash并与 head 做 paired build comparison。
2. 更新 `ort_pr28003_full_build_evidence.json` 和 `goal_round4_end_of_day_audit.json`，保持 build、runtime、formal proof 三个 gate独立。
3. 继续筛选与真实代码契约一致的 MindSpore/ORT narrow PR；标题与 exact diff不一致的候选继续拒绝物化为 verified case。

本轮结束时 goal 保持 active/paused-by-user，所有未闭合证据明确保留 `REVIEW`，legacy benchmark 与安全边界未改变。

## 第六十轮：2026-08-27 ORT-28003 paired build 与真实 provider runtime

### 本轮任务目标

在用户明确授权本地真实 executor 后，先完成上轮中断的 ORT-PR-28003 base `onnxruntime_provider_test` 构建，再以 exact base/head revision、固定 binary hash 和 allowlisted upstream GTest filters 收集真实 CPU RNN provider runtime 证据。授权不改变其余安全边界：不使用 OOM/超大 shape、不生成利用链、不接收外部模型或输入、不连接网络目标。

### 构建对称性完成

base `0fedb26c93e6c29882185715d5c2bb583a6d92b5` 从已有 build directory 单线程增量续建成功，`onnxruntime_provider_test` 完整链接。base 与 head 的 build evidence 现均绑定同一 target、`rnn_op_test.cc` manifest、CMake `3.31.10`、GCC `11.4.0` 和 exact binary digest：

```text
base SHA256: 6d3dc79a07cc129deef5da44a6158412f2e7df82a3ec91a14a38fd7d2ffc8c24
head SHA256: ec1bfff81a5e4f85419483f9a3efa6a323df3404ceb7b92d8bd7c808c4d1b952
```

新增 `paired_build_evidence.py`，其 `PAIRED_BUILD_VERIFIED` 只表示 pinned base/head configure 和 selected target build evidence 一致，明确不提升为 runtime 或 formal proof。

### 真实 executor 证据

新增 `gtest_runtime.py`，它只运行本地 pinned binary 的 allowlisted `RNNTest.*` filters：无 shell、stdin 为 DEVNULL、每个 filter 有 timeout、要求实际 run/pass/fail/skip count 全部符合计划，并把 source revision、target、binary SHA256 写回 output artifact。

focused direct runtime 结果：

```text
base shared controls:                  2/2 PASS
head direct + shared controls:         4/4 PASS
head RNN_seq_length_zero:              PASS
head RNN_forward_sequence_lens_with_zero: PASS
```

随后执行完整的非 disabled upstream RNN suite：

```text
base active RNNTest suite: 10/10 PASS
head active RNNTest suite: 12/12 PASS
GTest disabled tests:       1 per revision, intentionally not executed
```

head 比 base 多出的两条 official regression tests 正是全局 `seq_length=0` 与 batch-local `sequence_lens={2,0}` 的修复路径。它们在 complete provider target 内通过，说明 forward CPU RNN 对空序列/零长度 batch 给出定义的 `Y_h=0` 行为，而不是从无效时间步读取。

### Contract audit 与 no-uplift 设计

`rnn_helpers.cc` 的实际 predicate 是 `len < 0 || len > seq_length`，因此允许 `len==0` 和 `len==seq_length`；但诊断字符串仍写作 “`> 0` and `< seq_length`”。新增 `ort_pr28003_runtime_contract_audit.json` 记录此不一致。旧 `RNN_invalid_sequence_lens` GTest 包含 shape 错误与 `{0,5}` 中 `5 > seq_length` 的混合失败条件，因此只能作为邻接 input-validation control，不能被错误解释成“zero length 必须拒绝”的反证。

同时扩展 `contract_matrix.py`：

```text
runtime:          complete contract gate；仅 PASS 才可 MATRIX_VERIFIED
scoped_runtime:   reduced/bounded evidence；永不提升 full gate
operator_runtime: 实际 full target 的有限 subcase/suite evidence；仅展示，不提升 gate
```

ORT matrix 现在显示 actual local full provider target 的 active suite PASS，但因未安全触发 SafeMul/narrow oversized-dimension 边界，两个 arithmetic paths 仍为 `REVIEW`。新增 `paired_runtime_evidence.py` 复核 base/head revision、binary hash、focused `2/2`/`4/4`、suite `10/10`/`12/12`、失败/跳过数和 shared controls；结果为 `PAIRED_RUNTIME_EVIDENCE_VERIFIED`，且 `formal_proof=false`。

### 本轮交付与严格边界

主要 artifact：

```text
ort_pr28003_paired_build_evidence.json
ort_pr28003_base_gtest_runtime_evidence.json
ort_pr28003_head_gtest_runtime_evidence.json
ort_pr28003_base_full_rnn_suite_evidence.json
ort_pr28003_head_full_rnn_suite_evidence.json
ort_pr28003_paired_runtime_evidence.json
ort_pr28003_runtime_contract_audit.json
```

本轮实际提升为“pinned base/head paired build + complete active default-CPU RNN suite runtime evidence”。它不是全输入、全 provider、全配置或形式化语义证明。仍未覆盖的维度包括：SafeMul/narrow 的非 OOM oversized-dimension runtime、reverse/bidirectional zero `sequence_lens`、CUDA/TensorRT/OpenVINO/DML 等 execution providers、full target sanitizer build，以及所有未声明 caller/error paths。

回归、registry、lattice、legacy dataset 与 benchmark 均在本轮末保持有效；12-case evidence lattice 仍为 `FULL_GATED_LOCAL 4`、`SCOPED_RUNTIME 6`、`LOCAL_STATIC 2`，legacy strict `16/31`、legacy `20/31`、guarded `3` 未改变。

## 第六十一轮：MindSpore 小范围 checked-addition 候选筛选

### 筛选目标与证据来源

在 ORT-28003 real executor 阶段完成后，继续扩展候选队列，但不把“标题有 overflow”误写成“可验证修复”。公共搜索服务本轮不可用，因此没有凭搜索摘要生成候选；改为只读审计本地已存在的 MindSpore Git history、merge topology、exact diff、blob ID 和 sparse source checkout。

### 被拒绝或保留 REVIEW 的候选

- `!90173 Fix std::accumulate overflow` 与此前 `!90890` 的 final diff 都是 200-file cross-backend/type migration，不是单一可审计 contract，继续 `DEFER_BROAD_SCOPE`。
- `!89359 add integer overflow check in nnacl and lite-java` 改动 13 个 Lite/NNACL/Java 文件，超过当前 first-class case 的小 scope 上限。
- `!80416 [ASAN] fix heap-buffer-overflow` 虽只改一个 `convert_utils.cc`，但当前 exact diff 是 vector-length compatibility contract 调整；title 到具体 heap-overflow 因果尚缺调用路径证据，因此不提升为 contract-matching candidate。
- `!75717 fix aclnn heap overflow` 也在 Ascend ACL 路径，且单行 tuple-size 调整不能在缺少调用约束时自动被认定为完整 memory-safety repair。

### MS-PR-87710 source-only materialization

`!87710 avoid overflow` 满足小范围门槛。local merge topology 固定为 base merge parent `d15b70d59b3ae0a36f41cd67753109092cf006a0`、merge `6ae69d885df612affe27482a3dafb06386ca6ea2`、head branch commit `fd723d1b20884417a4090438b568ebb8e62238ee`。final diff 仅修改：

```text
mindspore/ops/kernel/ascend/acl_ir/op_api_cache.h
4 insertions, 0 deletions, git diff --check PASS
```

使用 detached sparse worktree 只检出该 header，且两侧 clean。base/head Git blob 分别为 `09aea0c8e1696170ea23c5ffd6ce57df4f327a62` / `860a61d409b9eb65a6b7828730f7ef468cb65444`；SHA256 分别为 `c1ad1ace59ae1b268228c19ab8b97f4405db262b14daeab85fa5aaaec8abdfd4` / `4eb8687703df265aadd0e9f0547da456c74340c563cb72a8ff222d3ba9f8a83f`。

head 在 `MemcpyToBuf` 增加：

```cpp
if (MS_UNLIKELY(static_cast<uint64_t>(g_hash_offset) > SIZE_MAX - size_expression)) {
  MS_LOG(ERROR) << "Hash buf is overflow.";
  return;
}
```

这条 guard 位于所有 `g_hash_offset + size_expression` 和 `g_hash_offset += size_expression` 之前，阻止加法在已有 buffer-capacity 比较之前 wrap。新增 `checked_addition_contract.py` 强制检查 paired source 中的 base/head delta、guard lexical ordering 和 return；它在真实 source 上返回 `STATIC_CONTRACT_DELTA_VERIFIED`，但 scope 仅限 source text/ordering，`formal_proof=false`。

通用 `cwe_detect.py --cwe 190` 在两侧都留下同一条低置信 `read_size_unchecked` memcpy residual，说明它当前不理解该 representability guard。该残留被显式记录为 detector coverage gap，不能用来否定 static contract，也不能用来宣布全路径修复。

### 状态与边界

`ms_pr87710_screening.json` 与 `ms_pr87710_static_contract_evidence.json` 现记录为 `OFFICIAL_LOCAL_SOURCE_SCOPE_AND_STATIC_CONTRACT_VERIFIED_REVIEW`。它只加入 registry 的 `candidate_sources`，不加入 12-case registry、不改变 lattice 分布、不影响 legacy benchmark。

仍缺：bounded non-OOM unit fixture、Ascend ACL provider/runtime、其他 hash-buffer write entry points 的 symmetry inventory、对 offset/size 起源与并发语义的调用链分析以及形式化证明。本轮未 build、未运行 executor、未连接网络目标、未构造 OOM/利用输入。

## 第六十二轮：ORT-PR-28003 full-build source scope integrity

### 触发与方法

收到另一份工作树可能含 unrelated modifications 的审计提示后，没有把它泛化到已执行 build/runtime 的 worktree；而是直接只读核对 `pr28003_full_base_probe` 与 `pr28003_full_probe`。两侧 `git rev-parse HEAD` 分别精确返回 base `0fedb26c93e6c29882185715d5c2bb583a6d92b5` 和 head `795675a77ebb898302c5798bd6247658db165d14`，完整 `git status --porcelain` 都为空。

### 完整 PR source scope

此前 provider runtime 主要绑定 RNN source/test；本轮补齐 exact PR 的四文件 scope：

```text
safeint.h:       45 additions, 0 deletions
rnn.cc:          38 additions, 20 deletions
safeint_test.cc: 38 additions, 0 deletions (new file)
rnn_op_test.cc: 103 additions, 0 deletions
```

`git diff --check` PASS。`ort_pr28003_source_scope_integrity.json` 记录每个文件的 base/head Git blob 与 SHA256。对于新增 `safeint_test.cc`，base object absence 由 `git cat-file -e` 的 object-not-found 结果确认，而不是将不存在文件当成 hash failure。

### 绑定边界收紧

`onnxruntime_provider_test` 的 generated manifest 已证明 `rnn_op_test.cc` 被编译，且 exact base/head binary 实际运行过 focused controls 和 active RNN suite。它**不**自动证明新增 `safeint_test.cc` 被该 target 编译或执行；full build evidence 现在明确把该项标为 `NOT_CLAIMED_BY_THIS_PROVIDER_TARGET_EVIDENCE`。这条区分避免把 SafeMul source/test addition 错写成 full provider runtime coverage。

完整 RNN suite 继续只覆盖 CPU RNN behavior；SafeMul/narrow overflow、SafeIntTest target membership/runtime、非 CPU provider 和形式化证明都继续 `REVIEW`。本轮重新通过 cwe-repair regression、paired build/runtime validators、registry、legacy dataset 和 benchmark；12-case registry 与 strict baseline 未变化。

## 第六十三轮：ORT-PR-28003 SafeInt added-test paired build and no-OOM feasibility

### Added-test target binding

新增的 `onnxruntime/test/common/safeint_test.cc` 不属于此前运行的 `onnxruntime_provider_test`；generated `DependInfo.cmake` 表明它属于 `onnxruntime_test_all`。为避免把 source presence 误写为已测试，本轮在相同 pinned base/head、Debug、`/usr/bin/c++`、Unix Makefiles 和 `-j1` 下仅 build 该 target：base manifest 有 108 个 `.cc`，head 有 109 个，唯一 source-set delta 是 `safeint_test.cc`。

base/head `onnxruntime_test_all` 都 build PASS；head 的 `safeint_test.cc.o` 实体存在。`ort_pr28003_safeint_build_evidence.json` 绑定 source SHA256、manifest source/object path、CMake cache 配置、target output path/size/SHA256 和新增 object size/SHA256。`added_test_target_build_evidence.py` 实际读取这些 artifacts，不再信任自述 `PASS`/boolean/count；结果为：

```text
valid:             true
verdict:           REVIEW
build_only_status: BUILD_ONLY_NOT_RUN
runtime_status:    NOT_RUN
```

`REVIEW` 是刻意设计：该 build evidence 不可写入 runtime field，也不会被 lattice/readiness 升级为 semantic/runtime PASS。回归增加了该集成约束，`not_run` 被显式识别为负向 runtime marker。

### SafeMul runtime feasibility

`RNN<float>::Compute` 的 checked `SafeMul<int>(seq_length, batch_size)` 位于 validation、output/temp allocation 后的 GEMM 参数路径。普通正维度 overflow fixture 可能在到达该 guard 前要求巨大 X/output/temp allocation，因此不符合 no-OOM 约束。设计出一个零元素候选 `X=[50000,50000,0]`、`W/R=[1,0,0]`、`hidden_size=0`、optional outputs；它理论上可在零数据 allocation 下触发 `50000*50000 > INT_MAX`，但 `hidden_size=0` 是否是规范 RNN 输入仍待专用 probe 证明。本轮没有运行该候选，也没有修改 upstream test source。

因此 SafeMul/narrow provider runtime gate、reverse/bidirectional zero `sequence_lens`、non-CPU provider、full target sanitizer 和 formal proof 仍为 `REVIEW`。本轮 cwe-repair regression、真实 build artifact validator 和 Python/JSON compile checks 均通过；legacy strict benchmark 未修改。

## 第七轮：单资产全路径语义复核门禁

### 先回答目标边界

调查 2026-08-22 开发日志和此前迭代记录后，结论是：**只针对一个资产可以做可复核的全路径语义验证，但“全路径”必须指该资产显式声明的 contract scope，不是对所有输入、所有 provider、所有 configuration 的普适证明。** 开发日志把插件定位为“可复现、可审计、可迁移的输入契约验证组件”，并明确要求有限跨文件证据、不宣称完整数据流分析、不把理论 CWE 覆盖当作逐条运行闭环；同时要求真实 binary 的双向验证，不能用模拟 PASS 冒充语义证据。

因此单资产的可复核结论需要同时回答：资产是哪一个 exact base/head；source scope 和入口/调用路径是什么；CWE contract 的输入维度有哪些；每条路径是否有 static、symmetry、paired build、base/head runtime、malicious rejection 和 benign preservation evidence；provider/target/configuration/input domain 边界是什么；artifact 是否可由 SHA256、case ID 和字段断言重放。`ASSET_SCOPE_COMPLETE` 只表示这些显式义务全部闭合；`formal_proof=false`、`universal_claim=false` 是强制约束。

### 插件实现

新增 `scripts/asset_semantic_contract.py` 作为阶段 4 门禁，并在 `SKILL.md` 中加入用法。validator 支持对象和数组路径断言，实际读取 evidence JSON、检查 SHA256、case ID、formal-proof 声明和字段值；再分别计算 `artifact_integrity` 与 `scope_complete`。证据完整但语义维度缺失时不会降级为“部分 PASS”，而是保留 `REVIEW` 并列出 missing gates。

新增 `examples/ort_pr28003_asset_semantic_contract.json` 作为首个真实单资产 contract。它声明 pinned ORT base/head、CPU/default provider、两个 build target、Debug/C++17、有限 RNN fixtures 和 no-OOM 边界，并绑定 provenance、source scope、paired build/runtime、contract matrix、SafeInt build-only 和 feasibility artifacts。validator 结果：

```text
artifact_integrity: true
scope_complete:     false
verdict:             REVIEW
missing_gates:       26
universal_claim:     false
formal_proof:        false
```

这说明 ORT 的证据包本身已具备可复核完整性，但资产声明的语义 scope 尚未闭合；SafeMul/narrow overflow、base/head malicious/benign 双向 contract、reverse/bidirectional zero-lens、provider matrix 和完整 symmetry/static closure 仍缺证据。没有因为 12/12 CPU suite、common-test build 或 reduced harness 而越级。

回归新增三类约束：完整合成资产可以通过 `ASSET_SCOPE_COMPLETE`；任一路径 runtime gate 改为 `REVIEW` 必须被拒；证据篡改必须报告 SHA256 mismatch。数组断言和 ORT asset contract 均验证通过，`cwe-repair regression: PASS`，legacy strict benchmark 未修改。

## 第六十四轮：泛用性评估与 inventory completeness 门禁

### 今天的目标判断

围绕“具身智能 AI 组件全路径语义验证正确”的目标，结合本开发日志、螺旋记录、12-case registry 和 34-finding dataset 做了资产成熟度审计。结论是：现有组件足以完成**研究型 MVP**，但还不能宣称跨资产、全输入、全 provider/configuration 的普遍语义正确。更准确的定位是：

> 面向具身智能 AI 组件的资产级输入—状态—执行契约全路径语义验证。

其中“全路径”必须指资产显式声明并经过 inventory 复核的外部边界、调用路径、输入维度和执行 sink；`ASSET_SCOPE_COMPLETE` 只表示该有限声明范围全部闭合，`universal_claim=false`、`formal_proof=false` 永久保留。

### 当前组件成熟度（工程估计，不是 benchmark 分数）

- 检测、修复建议、真实 bounded runtime、对称性和 evidence 编排原型：约 `70%–80%`；
- 单资产声明范围闭合：约 `50%–60%`，NCNN 最接近；
- 跨资产泛用性：约 `30%–40%`；
- 具身控制/消息/协议副作用语义：约 `15%–25%`；
- 所有输入/provider/configuration 的 universal correctness：不作为有限插件目标。

现有素材可以分成四类试点：NCNN parser 作为第一个 scope-complete 正例；ORT-PR-28003 作为证据完整但语义未闭合的严格 `REVIEW` 例；MindSpore 作为跨框架迁移例；Agibot/AimRT/XR 作为消息、控制副作用、认证和协议契约的后续扩展。dataset 有 5 类组件、34 条 finding；registry 有 12 个 case，当前仍为 `FULL_GATED_LOCAL=4`、`SCOPED_RUNTIME=6`、`LOCAL_STATIC=2`。强 runtime 闭环主要集中在 NCNN，其他组件不能合并外推。

### 泛用性增强：先补清单完整性

单纯人工填写 `paths` 不能证明没有遗漏路径，因此在 `asset_semantic_contract.py` 中加入默认资产级 gate `inventory_completeness`。资产 contract 现在必须声明：

- inventory enumeration method 和 source basis；
- external input boundaries；
- reachable sinks；
- 与 `paths` 一致的 declared path IDs；
- 明确的 unverified 项。

缺少 inventory 会同时报告 artifact error 和 `asset.inventory_completeness` missing；声明 `PASS` 但仍有 unverified 项会被拒绝；path ID 不一致也会被拒绝。该 gate 将来应绑定 compile database、target manifest、符号/AST 枚举和显式 exclusions，避免“只验证被手工挑出的路径”。

ORT contract 已绑定 `ort_pr28003_path_inventory.json` 作为 inventory evidence，但该清单仍明确列出 complete source-to-sink enumeration、非 CPU provider、全部配置组合和 SafeMul/narrow runtime stimulus 等未验证项，所以结果保持：

```text
artifact_integrity: true
scope_complete:     false
verdict:             REVIEW
missing_gates:       27
```

这不是 ORT 代码失败，而是 asset-level semantic gate 按设计阻止证据越级。下一正式正例应先把 NCNN 的 TEXT/BIN parser contract 规范化，证明一个真实资产可以达到 `ASSET_SCOPE_COMPLETE`；之后再用 MindSpore、Agibot/AimRT 和 XR 的不同契约族验证迁移边界。

## 第六十五轮：首个真实 ASSET_SCOPE_COMPLETE 子契约

### 目标与范围

本轮选择已合并的 NCNN PR #6383，而不是仍处于 open/unmerged 状态的 #6922。声明范围严格收窄为：

```text
NCNN::Net::load_param(TEXT)
  -> ParamDict::load_param
  -> pdlr != 0
  -> delete layer
  -> Net::clear
  -> return -1
```

资产 contract 绑定官方 PR、精确 base/head revision、`src/net.cpp` source hash、同配置 `release + Unix Makefiles + CPU` build cache、base/head harness hash、malicious/benign fixture hash、detector static artifact、symmetry artifact 和 inventory artifact。

### 新增语义

修复验证不能把 base 的旧失败行为错误写成 `runtime_base=PASS`。因此 `asset_semantic_contract.py` 增加默认 path gate `preimage_witness`：

- base 必须在同一恶意 fixture 上观察到预期不安全行为；
- `malicious_rejected` 必须是未完成比率，例如 `0/1`；
- `unsafe_behavior_observed=true`；
- infrastructure failures 必须为 `0`。

这样才准确表达 `base SIGSEGV -> head ret=-1` 的修复前后语义，而不要求脆弱版本先“通过”。

### 结果

新增并通过：

- `ncnn_pr6383_asset_evidence.py`：验证 WSL pinned worktree、git revision/clean state、source/cache/harness/fixture SHA-256、build configuration 和 recorded runtime pair；
- `ncnn_pr6383_paramdict_failure_evidence.json`；
- `ncnn_pr6383_text_paramdict_static_evidence.json`；
- `ncnn_pr6383_text_paramdict_path_inventory.json`；
- `ncnn_pr6383_text_paramdict_symmetry.json`；
- `ncnn_pr6383_asset_semantic_contract.json`；
- `ncnn_pr6383_paramdict_failure_evidence_validation.json`。

验证输出：

```text
NCNN evidence binding: valid=true, errors=[]
asset semantic contract: artifact_integrity=true
asset semantic contract: scope_complete=true
asset semantic contract: verdict=ASSET_SCOPE_COMPLETE
missing_gates=[]
```

首个真实正例的含义是“NCNN #6383 的一个显式 TEXT ParamDict failure-cleanup 子契约已闭合”，不是整个 NCNN、整个 PR、所有 parser branch、所有输入或所有 provider 的全路径证明。该 contract 明确排除 BIN、另外两个 TEXT failure branch 以及 ASan instrumentation；现有 build 为 `NCNN_ASAN=OFF`，因此不宣称 sanitizer 覆盖。

### 回归与后续边界

`test_cwe_repair.py` 已加入真实 #6383 contract 的 `ASSET_SCOPE_COMPLETE` 回归；synthetic regression 同时覆盖 preimage 缺失/错误、inventory 缺失、inventory 虚假 PASS、artifact tamper、universal/formal claim 拒绝。ORT-PR-28003 继续保持 `artifact_integrity=true`、`scope_complete=false`、`REVIEW`。

## 第六十六轮：NCNN #6383 从单路径扩展至双 TEXT 路径

### 新增路径

新增有限 TEXT fixture `ncnn_pr6383_text_layer_load_failure.param`：

```text
Interp interp 0 1 out 0=4
```

该文件使 `ParamDict` 正常解析，再由 `Interp::load_param` 因 `resize_type=4` 返回 `-1`，精确到达 `Net::load_param` 的 `lr != 0` 分支。它不执行 forward、不访问网络、不触发大分配。

同一 hash-bound release CPU harness 的本地 base/head 结果为：

```text
base: unsupported resize type 4 -> layer load_param failed -> exit 139
head: unsupported resize type 4 -> load_param ret=-1 -> exit 1
benign: base/head 均 exit 0
```

### 证据与门禁

新增：

- `ncnn_pr6383_text_layer_failure_evidence.json` 及其 validation；
- `ncnn_pr6383_text_layer_static_evidence.json`；
- `ncnn_pr6383_two_text_failure_inventory.json`；
- `ncnn_pr6383_two_text_failure_symmetry.json`；
- `ncnn_pr6383_two_text_failure_asset_contract.json`。

新 contract 的声明路径包括 `ParamDict::load_param` 失败和 `layer->load_param` 失败，二者均通过 static contract、symmetry、paired build、preimage witness、head runtime、恶意拒绝、合法保持与对应输入维度 gate：

```text
artifact_integrity=true
scope_complete=true
verdict=ASSET_SCOPE_COMPLETE
errors=[]
```

### 仍未声明的路径

该双路径结果仍然不是完整 #6383。TEXT custom CPU fallback 和三个 BIN 失败分支没有单独有限 fixture 与 base/head runtime，因此保持 exclusion，不被 inventory 或结论暗中吸收。实际执行配置为 CPU release、`NCNN_VULKAN=OFF`、`NCNN_ASAN=OFF`，不作 GPU 或 sanitizer 覆盖主张。

### 今日验证与安全边界

- `cwe-repair regression: PASS`；包含完整资产、缺失 runtime、缺失 inventory、inventory 未验证项和篡改 artifact 回归；
- ORT asset validator：`artifact_integrity=true`、`scope_complete=false`、`REVIEW`；
- Python compile 与全部 JSON parse：`PASS`；
- 没有新增 target executor、网络目标、OOM/超大分配或利用链；
- legacy strict benchmark 和现有 12-case registry 未修改。

## 第六十九轮：BIN paired build 绑定复核

本轮为 NCNN #6383 的 BIN `ParamDict::load_param_bin` 和 BIN `layer->load_param` 分支建立了隔离 base/head harness build，使用相同 Release CPU 参数并复跑有限 fixture：

```text
BIN ParamDict: base exit=139, head ret=-1/exit=1, benign base/head exit=0
BIN layer load_param: base exit=139, head ret=-1/exit=1, benign base/head exit=0
```

运行语义观察成立，但严格 artifact binding 仍保持 `REVIEW`。原因是 wrapper CMake cache、pinned NCNN library cache、harness source UNC 路径和 base/head benign fixture hash 必须分别绑定；手写 evidence 中出现路径/哈希字段错误时，validator 正确拒绝升级。新增 `ncnn_bin_evidence_validate.py` 与 `ncnn_pr6383_bin_binding_review.json`，不把 runtime observation 冒充为 `ASSET_SCOPE_COMPLETE`。

Vulkan/custom CPU fallback 继续处于 `REVIEW`：pinned worktree 缺失 glslang submodule，`NCNN_VULKAN=ON` 尚未形成可审计 paired build。当前唯一严格闭合的仍是两条 TEXT parser failure path；BIN 两条路径待 UNC artifact 字段规范化后再升级。

## 第七十一轮：custom CPU fallback 可达性边界

审计 `Net::load_param(TEXT/BIN)` 后确认，custom CPU fallback 不是普通 CPU parser 路径：它要求 `NCNN_VULKAN=ON`、有效 Vulkan device，并且需要用户注册 custom layer 或 overwrite layer。当前 pinned paired builds 为 `NCNN_VULKAN=OFF`，既有 harness 也未注册 custom layer，因此该分支在当前安全 scope 中不可达。

新增 `ncnn_pr6383_custom_cpu_fallback_review.json`，明确记录 `config-reachable`、`NOT_RUN` 和必要前置条件。没有把不可达分支伪造成 runtime PASS，也没有修改 pinned source/submodule。

截至本轮，四条普通 TEXT/BIN parser failure path 的 contract 已通过 `ASSET_SCOPE_COMPLETE`；custom CPU fallback 与 Vulkan fallback 继续为 `REVIEW`，ORT-PR-28003 继续为 `REVIEW`。

## 第七十轮：NCNN #6383 四条普通 parser failure path 闭合

本轮将 BIN runtime 观察升级为严格 artifact binding。为避免原始 build cache 与后置 harness 混淆，使用独立的 `build_pr6383_bin_before/out` 和 `build_pr6383_bin_after/out` paired CMake harness，并同时绑定 pinned NCNN library cache、harness、harness source、有限 binary fixtures 与 benign fixture。

独立 BIN validator `ncnn_bin_evidence_validate.py` 直接按 evidence 中路径计算 SHA-256，最终输出：

```text
valid=true
verdict=NCNN_PR6383_BIN_ARTIFACT_BINDING_VERIFIED
runtime_status=RECORDED_LOCAL_BASE_HEAD_PAIR
errors=[]
```

随后新增生成器 `build_ncnn_four_path_contract.py`，从实际 artifacts 动态计算 hash，生成 `ncnn_pr6383_four_parser_paths_asset_contract.json`。四条普通 parser failure path 均通过 static contract、symmetry、paired build、preimage witness、head runtime、negative rejection、benign preservation 和 dimension gates：

```text
artifact_integrity=true
scope_complete=true
verdict=ASSET_SCOPE_COMPLETE
errors=[]
```

本结果的声明范围是 CPU release、`NCNN_VULKAN=OFF`、`NCNN_OPENMP=OFF`、`NCNN_ASAN=OFF` 下的 TEXT/BIN 普通 parser failure cleanup。Vulkan layer fallback、TEXT/BIN custom CPU fallback 仍没有可审计 Vulkan paired build，继续保持 `REVIEW`；这不是整个 PR #6383 或所有 NCNN parser/input/provider/configuration 的 universal/formal proof。

## 第七十二轮：Vulkan/custom fallback 机器可检查边界

本轮检查了本地所有可复用 Vulkan/glslang artifacts。没有发现 `glslangTargets.cmake`、可用 Vulkan NCNN cache 或完成配置的 paired build；唯一新建的 Vulkan cache 明确记录 `GLSLANG_TARGET_DIR=GLSLANG-NOTFOUND`，CMake 在 submodule 缺失处停止。

新增 `ncnn_pr6383_fallback_reachability_matrix.json`，分别记录 TEXT 和 BIN Vulkan-to-CPU fallback 的源码行、前置条件、当前 `REVIEW/NOT_RUN` 状态和安全边界。该矩阵确认两个分支是 `config-reachable`，但不属于当前 `NCNN_VULKAN=OFF` contract；没有初始化 submodule、修改 pinned source、执行 forward 或运行网络目标。

四条普通 TEXT/BIN parser failure path 仍通过 `ASSET_SCOPE_COMPLETE`，Vulkan fallback 与 TEXT/BIN custom CPU fallback 保持 `REVIEW`。ORT-PR-28003 继续保持 `artifact_integrity=true`、`scope_complete=false`、`REVIEW`。

## 第六十七轮：Vulkan CPU fallback 路径可达性复核

本轮尝试验证 `Net::load_param(TEXT)` 中 Vulkan layer 降级到 CPU 后再次执行 `layer_cpu->load_param(pd)` 的 failure branch。选择 `Convolution1D dynamic_weight=1` 作为有限触发候选，并新增 `ncnn_pr6383_vulkan_fallback_path.cpp`、两个有限 fixture 与 inventory。

Vulkan headers 与 ICD 文件存在，但为保持 pinned source provenance，未初始化或修改 submodule。独立 Vulkan build 使用 `NCNN_VULKAN=ON`、`NCNN_SYSTEM_GLSLANG=ON` 配置失败：

```text
system glslang lacks glslang-config CMake target
The submodules were not downloaded!
CMake: Configuring incomplete
```

因此 fallback runtime base/head 没有执行，新增 `ncnn_pr6383_vulkan_fallback_review.json`，结论为 `REVIEW`。后续若要闭合，应在独立 source snapshot 中补齐 glslang provenance、Vulkan build cache、设备信息与 base/head runtime，不应直接修改 pinned worktree。

当前 #6383 的两条 TEXT 路径仍为 `ASSET_SCOPE_COMPLETE`；Vulkan fallback、TEXT custom CPU fallback 以及 BIN failure paths 继续保持 exclusion/REVIEW，不能升级为完整 PR scope。

## 第六十八轮：尽量推进 BIN 与 Vulkan 相关三类路径

### BIN 路径观察

新增 `ncnn_pr6383_bin_error_path.cpp`，调用真实 `Net::load_param_bin`。在现有 CPU release base/head library 上分别完成了两类有限 binary fixture：

- `ParamDict::load_param_bin` EOP 截断：base 继续解析并最终 `exit=139`，head 返回 `-1/exit=1`；
- binary `Interp` 的 `load_param` 失败（`resize_type=4`）：base `exit=139`，head 返回 `-1/exit=1`。

官方 `squeezenet_v1.1.param.bin` 在 base/head 均返回 `0`，说明 benign preservation 观察成立。新增 `ncnn_pr6383_three_branch_runtime_observation.json` 保存这些结果。

但严格 artifact binding 仍为 `REVIEW`：BIN harness 是在原始 CMake build 完成后手工编译的，没有进入原始 paired-build cache 的目标产物，因此不能把这些运行观察升级为 hash-bound `ASSET_SCOPE_COMPLETE`。`ncnn_pr6383_bin_failure_evidence_validation.json` 明确记录该限制。

### Vulkan 与 custom CPU fallback

仍尝试了 TEXT/BIN Vulkan fallback 所需的独立配置。系统存在 Vulkan header/ICD，但 pinned worktree 缺少 glslang submodule，系统 glslang 没有可用 CMake target；`NCNN_VULKAN=ON` 配置停止于：

```text
The submodules were not downloaded!
Configuring incomplete
```

因此 TEXT custom CPU fallback、BIN custom CPU fallback 和 Vulkan layer fallback 均无 base/head runtime。新增 `ncnn_pr6383_vulkan_fallback_review.json`，保持 `REVIEW`，没有修改 pinned worktree 或初始化 submodule。

### 本轮结论

本轮最大化了可验证范围，但不隐藏构建边界：四条 TEXT/BIN 普通 parser failure paths 中，前两条 TEXT 已严格 `ASSET_SCOPE_COMPLETE`，两条 BIN 只有未绑定本地 runtime observation；三类 Vulkan/custom fallback 仍受 paired Vulkan build 缺失阻塞。legacy benchmark、原始 pinned source 和 12-case registry 未修改。


## 第七十三轮：ORT-PR-28003 narrowing scoped materialization

本轮优先 materialize ORT-PR-28003 的 `rnn-narrowing-contract` 单路径声明。新增生成器 `build_ort_narrowing_contract.py` 和标准格式 contract `ort_pr28003_rnn_narrowing_scoped_contract.json`，绑定 exact base/head provenance、source scope、CWE-190 contract、RNN `Compute` 调用路径、paired configure/build、CPU provider 双向 finite GTest runtime、SafeInt/build artifacts 与 bounded fixture evidence。

验证结果：

```text
artifact_integrity=true
scope_complete=false
valid=true
verdict=REVIEW
errors=[]
```

保持 `REVIEW` 是有意且可审计的：inventory 仍列出未验证项，`SafeMul<int>/narrow<int>` 没有安全的专属恶意 runtime witness；现有 bounded reduced fixture 只能证明有限 checked arithmetic 行为和 benign preservation，不能替代 full ORT provider semantic closure，也不能使用 OOM/超大输入补证。


## 第七十四轮：ORT bounded narrowing witness 分层

本轮复核了 `ort_pr28003_rnn_verify.cpp`、base/head reduced arithmetic fixture 与 exact ORT SafeInt tests。bounded reduced runtime 实际具有 malicious `2/2` rejection、benign `1/1` preservation、infrastructure failures `0`，但其 binary 是从抽取的 arithmetic contract 编译，不是完整 `RNN<float>::Compute` provider executor。

因此更新 `build_ort_narrowing_contract.py` 和标准 contract：reduced witness 被准确绑定为 scoped evidence；完整 ORT narrowing path 的 `negative_rejection` 与 `safe_mul_int_shape` 继续为 `REVIEW`，而不是把 reduced fixture 升格为 upstream full-path proof。当前 ORT narrowing contract 输出 `artifact_integrity=true`、`scope_complete=false`、`valid=true`、`verdict=REVIEW`、`errors=[]`。


## 第七十五轮：SafeInt 聚合测试执行边界

检查了 exact ORT `onnxruntime_test_all` build artifact 和 upstream GTest plans。`safeint_test.cc` 已编译进 head `onnxruntime_test_all`，但当前只有约 948MB 聚合测试 binary，没有独立 SafeInt target 或已有的 SafeInt-only 过滤运行证据。为避免把大聚合 binary 的 build PASS 误写成 SafeInt runtime PASS，本轮新增 `ort_pr28003_safeint_runtime_decision.json`，明确 `SafeIntTest.*` 为 `NOT_RUN`，并列出升级所需的独立 target/filter、base/head 输出、命令与 hash 绑定条件。

该决定保持安全边界：不执行未独立归因的聚合测试，不使用外部输入、网络目标、OOM/超大输入或 exploit chain。ORT narrowing contract 继续为 `artifact_integrity=true`、`scope_complete=false`、`REVIEW`。


## 第七十六轮：SafeInt head runtime 物化

本轮使用 exact head `onnxruntime_test_all` 的精确 GTest filter `SafeIntTest.*` 运行新增 SafeMul 测试。base 不包含该 head-added suite，head 实际输出为 4/4 PASS：普通乘法、同变量乘法、初始 cast overflow、乘法 overflow。新增 `ort_pr28003_safeint_runtime_evidence.json`，绑定 head revision、aggregate binary SHA-256、精确 filter、测试计数和安全边界；base 侧记录为 `NOT_APPLICABLE`，不伪造对称运行。

更新后的 narrowing contract 结果为 `artifact_integrity=true`、`scope_complete=false`、`valid=true`、`verdict=REVIEW`，只剩 inventory completeness 与完整 RNN Compute negative rejection 缺口。SafeMul dimension 已有真实 head helper runtime PASS，但没有使用 OOM/超大输入补证。


## 第七十七轮：ORT narrowing scoped inventory 完整化

本轮新增 `ort_pr28003_narrowing_scoped_inventory.json`，将 `rnn-narrowing-contract` 的声明范围具体绑定到 CPU/default provider、`onnxruntime_provider_test` 与 `onnxruntime_test_all`、Debug/C++17/Unix Makefiles、RNN `Compute`、`SafeMul<int>`、`narrow<int>`、有限 fixtures 和 SafeInt filters。

该 inventory 的 `inventory_completeness` 在声明 scoped path 内为 `PASS_WITHIN_DECLARED_SCOPED_PATH`，但仍明确列出两个未验证项：完整 RNN provider oversized-dimension malicious witness（不能使用 OOM）以及 base 对 head-added SafeIntTest 的对称执行。因此标准 asset gate 仍输出：

```text
artifact_integrity=true
scope_complete=false
valid=true
verdict=REVIEW
errors=[]
```

这一步没有删除未验证项，也没有把 scoped inventory 误报为 universal source-to-sink inventory。


## 第七十八轮：ORT RNN negative stimulus 边界确认

本轮逐段审计 exact head `rnn_op_test.cc` 及 base/head `RNNTest.*` 计划。上游测试只提供固定小维度、zero-extent、sequence_lens shape/out-of-range 控制，没有能在不分配巨大 tensor 的情况下到达 `RNN<float>::Compute` 的 SafeMul/narrow oversized rejection。`ort_pr28003_rnn_overflow.shape` 仅属于 reduced arithmetic harness，不是 full provider fixture。

新增 `ort_pr28003_rnn_negative_stimulus_review.json`，记录 `found_safe_upstream_negative=false`、已有邻接 controls、不可替代范围和 no-OOM promotion 条件，并将该 artifact 绑定到 narrowing contract 的 `negative_rejection` gate。结果继续为 `artifact_integrity=true`、`scope_complete=false`、`valid=true`、`REVIEW`，没有伪造 full-provider malicious evidence。


## 第七十九轮：ORT SafeMul helper 单资产闭合

本轮将 contract 合法缩小到 PR #28003 新增的 `SafeMul<T>` helper，而不是把 helper 测试冒充完整 `RNN<float>::Compute` 路径。新增 `build_ort_safeint_contract.py` 与 `ort_pr28003_safeint_helper_asset_contract.json`，绑定 exact provenance、changed source scope、SafeIntTest filter inventory、paired build、head 4/4 runtime、initial-cast overflow 与 multiply overflow rejection、benign multiplication 和安全边界。

标准 gate 输出：

```text
artifact_integrity=true
scope_complete=true
valid=true
verdict=ASSET_SCOPE_COMPLETE
errors=[]
```

该结论严格只覆盖 `SafeMul<T>` helper 的显式声明范围。base 对 head-added suite 为 `NOT_APPLICABLE`，并非 base 同测试 PASS；完整 RNN narrowing、allocation、sequence_lens、非 CPU provider 和所有配置仍不在此 helper contract 内。原 `ort_pr28003_rnn_narrowing_scoped_contract.json` 继续保持 `REVIEW`。


## 第八十轮：ORT narrow helper 归因边界

本轮检查 exact base/head 的 `onnxruntime/test/common/narrow_test.cc`。该文件及其 7 个测试在两侧都存在，属于 pre-existing auxiliary control，不是 PR #28003 changed scope；因此不能用它们替代 PR added `SafeMul` evidence，也不能把 generic `narrow<T>` 测试归因给 PR 修复。

新增 `ort_pr28003_narrow_helper_boundary.json`，记录 base/head presence、测试清单、`not_attributed_to_pr=true` 和安全边界。SafeMul helper contract 继续为 `ASSET_SCOPE_COMPLETE`；完整 RNN narrowing contract 继续为 `REVIEW`，不扩大声明范围。


## 第八十一轮：contract gate 强制 detect/repair-plan 证据

本轮审计发现标准 asset semantic validator 之前只把 `static_contract` 和 `symmetry` 作为结构化 path gates，没有强制每条声明路径绑定 detect 与 repair-plan artifacts。已将 `detect`、`repair_plan` 加入默认 path gates，并同步 NCNN 四路径、ORT SafeMul helper 和 ORT RNN narrowing contract generators；synthetic regression 继续覆盖 scope-complete 与 REVIEW 分支。

结果：NCNN 四路径 contract 和 ORT SafeMul helper contract 均通过新增 gates 并保持 `ASSET_SCOPE_COMPLETE`；ORT RNN narrowing 仍为 `REVIEW`，缺口未被 gate 扩展掩盖。


## 第八十二轮：全量 contract detect/repair-plan gate 迁移

本轮审计标准 validator 发现显式旧 `required_path_gates` 可以绕过新增的 detect/repair-plan 要求。已将 validator 改为无论 contract 是否显式声明旧列表，都强制加入 `detect` 与 `repair_plan` baseline gates；同步更新 NCNN/ORT contract generators，并为既有 NCNN TEXT contracts 补充真实 inventory/symmetry references。

全量正式 contract 审计结果：NCNN 三个 contract 与 ORT SafeMul helper 为 `ASSET_SCOPE_COMPLETE`；ORT full contract 为合法 `REVIEW`。该迁移没有修改 legacy strict benchmark。


## 第八十三轮：detect/repair-plan evidence role 审计

本轮检查新增 `detect`/`repair_plan` gates 是否会把任意 runtime artifact 冒充检测或修复证据。现有 contracts 的 references 已经绑定真实 detector/inventory、static matrix 或 repair-plan 断言；validator 增加可选 `evidence_role` 类型检查，保持向后兼容，不改变 legacy strict benchmark。

全量回归与 JSON/Python 审计通过。NCNN 四路径和 ORT SafeMul helper 继续 `ASSET_SCOPE_COMPLETE`；ORT full/narrowing contracts 继续按未验证维度输出 `REVIEW`。


## 第八十四轮：detect/repair-plan role enforcement 完成

本轮将 `evidence_role` 从可选类型校验升级为 detect/repair_plan gate 的必需 gate-level role：detect 必须声明 `detector`，repair_plan 必须声明 `repair_plan`。同步标注现有生成 contracts，并修复 synthetic regression 与 narrowing generator 输出。

全量正式 contract 审计无 errors：NCNN 三个 contract 和 ORT SafeMul helper 为 `ASSET_SCOPE_COMPLETE`，ORT full contract 合法 `REVIEW`。`cwe-repair regression` 与 compile/json 均通过；legacy strict benchmark 未修改。


## 发布收尾计划：具身智能 AI Runtime 安全复核 MVP

目标是在不夸大验证结论的前提下完成可审计发布，冻结当前已证明范围，不再为明天前的发布扩大新框架或高风险输入。

### P0：发布阻断项

1. 冻结发布范围：NCNN #6383 CPU Release 下四条普通 TEXT/BIN parser failure path；ORT #28003 `SafeMul<T>` helper scope；ORT full RNN、Vulkan fallback、custom CPU fallback、非 CPU provider 和其他配置继续 `REVIEW`。
2. 增加统一 `release_audit.py`：扫描正式 contracts，执行 hash/断言/schema 校验，检查 verdict、`universal_claim=false`、`formal_proof=false`、安全边界、临时路径和敏感文件。
3. 固化发布 schema：要求 asset/path/dimension gates，detect 与 repair_plan 必须分别声明 `evidence_role=detector` 和 `evidence_role=repair_plan`。
4. 使用文件哈希基线审计 legacy strict benchmark 和现有 12-case registry；工作目录不是 Git repository 时不得伪称 Git clean。
5. 生成最终 release report，逐资产列出 `ASSET_SCOPE_COMPLETE`、`REVIEW`、missing gates 和 evidence 数量。

### P1：具身智能定制化

1. 增加 `embodied_context` 元数据：输入来源、运行阶段、硬件/provider 依赖、失败模式、控制影响和真实机器人执行开关。
2. 增加具身风险标签：`model_input_boundary`、`shape_buffer_mismatch`、`provider_fallback`、`stale_state_risk`、`sensor_frame_risk`、`control_output_risk`、`lifecycle_cleanup`。
3. 将 repair_plan 定位为人工审阅前的受约束建议，要求保留 cleanup 顺序、TEXT/BIN 对称性、provider 语义和 fail-closed 行为，禁止静默 fallback、stale output、无界分配和网络执行。
4. 发布文档明确本组件面向模型/传感器/消息到 AI runtime 的输入边界，不连接真实机器人，不声称 universal correctness 或 formal proof。

### P2：延期能力

ROS/DDS/传感器/控制链路的完整规则、跨 provider 矩阵、patch apply/rebuild/retest、全程序 source-to-sink 图和领域 benchmark 延后到发布后迭代。

### 发布验收

```text
contract validator / cwe-repair regression / Python compile / JSON parse / hash binding = PASS
NCNN four-path = ASSET_SCOPE_COMPLETE
ORT SafeMul helper = ASSET_SCOPE_COMPLETE
ORT full RNN = REVIEW
Vulkan/custom fallback = REVIEW
legacy benchmark unchanged = hash-verified or explicit NOT_GIT_REPO
safety boundary = PASS
universal_claim=false / formal_proof=false
```


## 发布收尾复核：全量 review 与执行结果

### Review 发现与修复

1. 工作区根目录不是 Git repository，不能使用普通 `git diff` 作为 legacy benchmark 未修改的证据。已改为生成 `examples/release_baseline.json`，用 SHA-256 固定 `ncnn_history_benchmark_v2.json` 和 `embodied_ai_pr_case_registry.json`，并由 `release_audit.py` 校验；结果为 `PASS`。
2. 原有发布层没有统一审计入口。已新增 `scripts/release_audit.py`，汇总正式 contracts、预期 verdict、claim boundary、protected artifact hash、profile 完整性和敏感文件扫描。
3. 原有材料没有统一体现具身智能部署语义。已新增 `examples/embodied_ai_profile.json`，为五个正式 contract 标注 input source、runtime stage、hardware dependency、failure mode、control impact、risk labels 和 real-robot boundary。
4. schema 与证据等级分散在代码和日志中。已新增 `CONTRACT_SCHEMA.md`、`EVIDENCE_LEVELS.md`，并在 README 增加发布入口。

### 最终验收

```text
cwe-repair regression: PASS
release_audit: PASS
python/json validation: PASS
benchmark_v2 validate-only: valid=true, cases=8
protected benchmark/registry hashes: PASS
formal contracts: 4 ASSET_SCOPE_COMPLETE, 1 valid REVIEW
legacy strict benchmark: not modified by release work
real robot/network/exploit/OOM boundaries: disabled
universal_claim/formal_proof: false/false
```

### 发布结论

本次发布可以作为具身智能 AI runtime 安全复核 MVP 发布。发布结论严格限制在 NCNN CPU TEXT/BIN parser scope 与 ORT SafeMul helper scope；ORT full RNN、Vulkan/custom fallback、非 CPU provider、全配置矩阵和真实机器人链路继续保持 `REVIEW`，不得在发布说明中写成已完成全路径或全局正确性验证。


## 第二十八轮：发布门禁纳入回归与 profile schema 收紧

Review 发现 `release_audit.py` 仅检查 embodied profile 是否覆盖 contract 文件名，未检查每个条目的必需字段，存在空/不完整 profile 通过的风险；同时 release audit 还未被主 regression suite 调用。

已修复：

- `release_audit.py` 现在要求每个正式 contract profile entry 包含 `input_source`、`runtime_stage`、`hardware_dependency`、`failure_mode`、`control_impact`、非空 `risk_labels` 和 `real_robot_execution=false`。
- `test_cwe_repair.py` 直接调用 release audit，并断言 protected hashes、profile status 和整体 verdict 为 `PASS`。
- 增加 profile 负例验证：删除必需字段时审计结果为 `REVIEW`；恢复后审计重新为 `PASS`。

验证结果：

```text
cwe-repair regression: PASS
release_audit: PASS
invalid profile rejection: REVIEW / expected error present
python/json validation: PASS
legacy benchmark validation: valid=true, cases=8
```

本轮未扩大漏洞路径、未修改 legacy strict benchmark、未改变 ORT full RNN 的 `REVIEW` 结论。


## 第二十九轮：发布前一致性复核

按收尾计划完成 formal contract、release report、文档、legacy artifact 和路径安全复核。

### 发现与修复

`RELEASE_SCOPE.md` 最初只列 NCNN four-path contract，但 release audit 同时发布 single-path 和 two-TEXT 这两个 passing subset，形成读者可见的不一致。已明确：single-path 与 two-TEXT 是保留的可审计 passing subsets，four-path 是 NCNN 的发布覆盖结论；子集不外推到 Vulkan、custom fallback 或其他 parser 路径。

### 复核结果

```text
formal contract evidence references: 147 local references, no missing/nonlocal reference
formal contract source URLs: official HTTPS provenance only
cwe-repair regression: PASS
release audit: PASS
Python compile / JSON parse: PASS
legacy benchmark: valid=true, cases=8
PR case registry: valid=true, cases=12, legacy_dataset_impact=none
protected benchmark/registry hashes: PASS
```

发布范围未扩大：NCNN four ordinary CPU TEXT/BIN parser paths 与 ORT SafeMul helper 为 `ASSET_SCOPE_COMPLETE`；ORT full RNN 仍为合法 `REVIEW`，其 28 个缺失 gate 继续作为明确发布边界。


## 第三十轮：候选队列漂移与发布门禁 fail-closed

候选队列复核发现 `embodied_ai_pr_readiness_queue.json` 是 registry 的派生快照，但此前没有自动校验其是否已经漂移。已在 `pr_case_readiness.py` 新增 `--validate-queue` 和结构化 `validate_queue_snapshot`，比较 case count、gate count、priority/evidence-level counts、assessments 与 strict rule。

release audit 现在纳入 queue/registry snapshot consistency。另发现 profile、queue/registry 或 release baseline 缺失时旧逻辑可能保留 overall PASS；已修复为 fail-closed，对应缺失必定为 `REVIEW`。主 regression 新增 stale queue 和 missing profile 负例。

```text
queue snapshot validation: PASS (12 cases)
invalid stale queue: rejected by regression
missing embodied profile: REVIEW / expected error
cwe-repair regression: PASS
release audit: PASS
```

候选 queue 仍明确区分 readiness 与 strict eligibility：4 个 FULL_GATED_LOCAL 的 materialization-ready cases，8 个 complete-missing-gates cases；没有任何新增 case 进入 legacy strict benchmark。


## 第三十一轮：通用核心、评测边界与具身 callback 语义锚点

根据发布前架构与评测缺口复核，完成以下增量，未改变 legacy strict benchmark 或既有正式 contract 结论。

### 可移植核心

- 新增 `scripts/cwe_repair_cli.py`，把 detect/reach/symmetry/repair/plan/verify/contract/profile/evaluate/readiness/release-audit 暴露为不依赖 DSH 会话的 CLI；DSH skill 保留为首个 agent orchestration adapter。
- 新增 `CORE_ARCHITECTURE.md`，固定 portable core 与 adapter 的边界。
- 新增 `embodied_profile_validate.py`；release audit 改为复用其 profile schema 校验。

### 评测可复现性

- 新增 `evaluation_manifest.json` 和 `evaluation_summary.py`，明确 corpus、目标指标和基线状态。
- cwe-repair local artifact 标记为 measured-local；cppcheck、Semgrep、CodeQL 均为 `pending-environment`，禁止无命令/无映射的比较结论。
- release audit 现在 fail-closed 校验 evaluation manifest。

### 真实具身智能代码语义与受限模拟

- 新增 `embodied_callback_review.py`，source-hash-bound 审查本机 AGIBOT `DcuDriverModule::JointCmdCallback`：五个命令平行数组在 `name.size()` 循环中均缺长度守卫，静态可达 `xyber_ctrl_->SetMitCmd` 控制边界。输出 `STATIC_ONLY` / `REVIEW`。
- 新增 bounded local `joint_command_fake_sink.py` 和一恶意一合法 fixture。长度不匹配时 `ret=-1`、state_mutated=false、transform=0、fake_publish=0；合法输入时 `ret=0`、transform=1、fake_publish=2。双向 verify 为 `PASS`。
- 该结果固定为 `LOCAL_REDUCED_FAKE_SINK`：不是 AGIBOT/AimRT production runtime、不是真实 actuator、不是 asset semantic contract gate，也不计入 production runtime 或 `ASSET_SCOPE_COMPLETE` 指标。

### 验证

```text
cwe-repair regression: PASS
portable CLI contract/release-audit smoke: PASS
embodied profile validation: PASS
evaluation manifest validation: PASS
AGIBOT fake-sink malicious rejection 1/1; benign preservation 1/1
release audit: PASS
Python compile / JSON parse: PASS
```


## 第三十二轮：外部基线与 AGIBOT source-slice 环境可用性

为避免评测计划把环境缺失写成主观 pending，新增 `environment_probe.py` 和 `baseline_environment_probe.json`。本机探测结果：cppcheck、Semgrep、CodeQL、CMake、Ninja、clang++、g++ 均不可用；AGIBOT source snapshot 存在，但没有 `CMakeLists.txt` 或 `package.xml`。因此在不安装工具、不联网、不改变 pinned source 的条件下，外部基线与真实 C++ source slice 都不可运行。

`evaluation_manifest.json` 现在引用该环境 evidence；`evaluation_summary.py` 验证该 evidence，并拒绝把不可用的 cppcheck/Semgrep/CodeQL 错标为 `measured-local`。`release_audit.py` 继续 fail-closed 验证 evaluation manifest。

```text
evaluation manifest: PASS
environment probe: external_baselines_runnable=false; native_cxx_slice_runnable=false
cwe-repair regression: PASS
release audit: PASS
Python compile / JSON parse: PASS
```

没有安装额外依赖、没有修改 AGIBOT pinned source、没有执行网络或真实控制接口；fake-sink evidence 仍严格是 `LOCAL_REDUCED_FAKE_SINK`。


## 第三十三轮：ORT narrowing scoped contract 纳入完整发布 inventory

发布 inventory 审计发现 `ort_pr28003_rnn_narrowing_scoped_contract.json` 已由 regression 验证为正式、artifact-valid 的 `REVIEW` contract，但之前未列入 `release_audit.py` 的正式 contract 集合，导致 release report 漏报一个关键 ORT 证据边界。

已将该 contract 加入 release audit、expected verdict、embodied profile 和 RELEASE_SCOPE。审计现在覆盖 6 个正式 contracts：

```text
NCNN single / two-text / four-path: ASSET_SCOPE_COMPLETE
ORT SafeMul helper:                 ASSET_SCOPE_COMPLETE
ORT RNN narrowing scoped:           REVIEW (inventory_completeness, negative_rejection)
ORT full RNN:                        REVIEW (28 missing gates)
```

验证：`cwe-repair regression: PASS`、release audit `PASS`、完整 profile validation `PASS`。该变化没有升级 ORT RNN 结论，也没有修改 legacy strict benchmark。


## 第三十四轮：semantic contract 自动发现与 AGIBOT source-slice 计划

为避免 release audit 再次漏掉正式 contract，增加 formal contract discovery。合法命名为 `*_asset_contract.json`、`*_semantic_contract.json`、`*_scoped_contract.json`；matrix、static evidence 和 runtime audit artifacts 被排除。发现集合与 release expected-verdict inventory 不一致时 fail-closed 为 `REVIEW`。新增回归覆盖手工漏列 contract 的负例。

初版 discovery 规则过宽，随后规则过窄漏掉 `*_semantic_contract.json`；两次均由 fail-closed release audit 和 regression 捕获，最终正式 inventory 为精确的 6 个 contracts，release audit 恢复 `PASS`。

同时新增 `agibot_jointcmd_source_slice_plan.json` 和 `source_slice_plan_validate.py`。计划对真实 `JointCmdCallback`、`transmission.h` 和 `JointCommand.msg` 的 SHA-256 进行绑定，定义 callback-to-local-fake-sink slice 要保留的真实语义、允许替换的 AimRT/transport 接口、required runtime evidence、当前环境 blocker 与安全边界。计划本身有效，状态为 `REVIEW`；它不替代真实 source slice build。

```text
cwe-repair regression: PASS
formal contract inventory: PASS (6)
release audit: PASS
source-slice plan: valid=true, status=REVIEW
Python compile / JSON parse: PASS
```


## 第三十五轮：WSL pinned ORT executor 复核与有限 paired RNN control

Windows-host environment probe 只反映宿主工具缺失，不能用于否定 WSL executor。只读复核确认 WSL Ubuntu-22.04 中存在目标 commits 的 ORT full probes：base `0fedb26c93e6c29882185715d5c2bb583a6d92b5` 与 head `795675a77ebb898302c5798bd6247658db165d14`，均有 Debug/C++17 `onnxruntime_provider_test` 二进制。

对两个 pinned binary 使用同一有限 upstream filter：

```text
RNNTest.RNN_forward_direction_zigged_batch
base: PASS 1/1, 59 ms, sha256=6d3dc79a07cc129deef5da44a6158412f2e7df82a3ec91a14a38fd7d2ffc8c24
head: PASS 1/1, 48 ms, sha256=ec1bfff81a5e4f85419483f9a3efa6a323df3404ceb7b92d8bd7c808c4d1b952
```

结果写入 `ort_pr28003_paired_benign_control_evidence.json`。它只证明一个 shared finite CPU/default-provider RNN control 的 paired benign behavior；不替代 oversized SafeMul/narrow malicious rejection、full path inventory、all-provider coverage 或 formal/universal proof。因此 full ORT contract 继续为 valid `REVIEW`，28 个 missing gates 未删除。

AGIBOT source-slice plan 也修正了 environment 描述：WSL 有 C++/CMake executor，实际 blocker 是 AGIBOT snapshot 缺少 standalone CMake/package manifest、source-bound generated JointCommand type 与 official base/head repair pair。

```text
cwe-repair regression: PASS
source-slice plan: valid=true, status=REVIEW
release audit: PASS
ORT full semantic contract: valid=true, verdict=REVIEW (expected non-zero CLI)
Python compile / JSON parse: PASS
```
