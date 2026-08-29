# cwe-repair 开发日志（2026-08-22）

> 工具：DSH skill「cwe-repair」——针对 C/C++/Python 特定 CWE 类型的
> 「检测 → 修复 → 正确性验证」防御侧闭环。
> 日志覆盖：2026-08-20（构思）→ 2026-08-22（v7），完整记录设计决策、迭代动因、实测证据与教训。
> 作者：kaltsit-10（独立研究）；边界：防御侧、授权本地离线、不研究 RCE 利用链。

---

## 〇、动机与定位（为什么做这个工具）

- **导师建议**（原话要点）："找能升级到任意代码执行级别的漏洞本身就很难，做漏洞利用问 AI 还会被安全护栏限制。能不能从防御者角度设计自动化检测和修复某一种特定类型（内存越界、整数溢出、逻辑错误）的 bug？"
- **前期判断**（诚实评估）：检测/修复/验证单拎出来都是成熟红海（Coverity 2002、APR 2009、LLM 修复 2025 已产品化）；真正缺口是**组合 + 垂直场景**——「提交前最后把关 + 修复有效性证明」。
- **定位**：不是更强的扫描器，而是 **「修复正确性双向验证（恶意拒绝+合法不误拒）」+「成对入口对称性检查」**——后者经调研确认无同类工具。

---

## 一、v1 初始构建（2026-08-20 晚）

### 交付
```
.dsh/skills/cwe-repair/
├── SKILL.md                    # DSH skill 入口（frontmatter: name/description/whenToUse）
├── scripts/
│   ├── cwe_detect.py           # 阶段1 检测（规则模板，CWE-125/787/190/369/476）
│   ├── cwe_repair.py           # 阶段2 补丁生成（模板化，unified diff）
│   └── cwe_verify.py           # 阶段3 双向验证（恶意拒绝 + 合法不误拒）
└── examples/ncnn_blobidx_verify.json
```

### 设计决策
1. **模式来自实证**：detect 的规则模板不是凭空写的，是从 **NCNN/MindSpore/AGIBOT/AimRT/XR 的 28+ 真实漏洞**归纳（平行数组不互检、`map.at()` 作下标、双路径不对称、I/O size 无校验）；
2. **verify 是核心差异化**：A 方向（恶意 PoC 必须被拒 ret=-1）+ B 方向（合法输入必须不误拒 ret=0），用真实退出码/ASan 实证——现有工具（回归测试/静态 oracle/LLM 判别）都不做；
3. **skill 而非裸脚本**：以 DSH skill 形态分发，模型通过 `skill` 工具按需加载，符合 DSH 生态。

### 首次实测（闭环演示）
- **detect** → AimRT `json_convert.h` 命中 L170（AR-1 真实越界写点）；
- **repair** → 生成 `array_size_` 边界检查补丁（与人工修复思路一致）；
- **verify** → 模拟测试：修复版 PASS（恶意 exit=1 拒绝 + 合法 exit=0）、漏洞版 REVIEW（恶意 exit=139 崩溃被捕获）。

### 教训
- 模拟测试无法暴露真实环境的语义差异（exit code vs ret 输出 vs 信号码）——**必须真实二进制验证**（v5 验证了这点）。

---

## 二、v2 误报过滤器（2026-08-22 上午）

### 动因
MNN 全库扫描 893 命中，绝大多数是误报（`map[key]=` 插入语义、有守卫的循环、成员遍历）。

### 迭代
1. **过滤器**（`filter_false_positive`）：
   - `_is_map_insert`：`map[key]=` 赋值语义（合法）→ 过滤；
   - `_is_map_read`：纯 map 读（插入语义）→ 过滤；
   - `_has_guard_in_context`：同函数已有 `if(idx<0||idx>=size)` 守卫 → 过滤；
   - `_is_index_from_map_at`：`arr[map.at(k)]`（X1-9 模式，真实信号）→ **保留**。
2. **多轮调试**（记录真实踩坑）：
   - `map.at()` 豁免误伤 X1-9（`.at()` 结果作下标正是不安全）→ 修正为最高优先级保留；
   - `throw` 被误判为守卫（异常≠边界检查）→ 守卫正则收紧；
   - 等长检查 `==size()` 的嵌套括号让 `[^)]*` 失效 → 改为宽松匹配；
   - `_has_guard_in_context` 窗口从 3 行扩到 4 行（L71 守卫在窗口外）。

### 效果
MNN core：893 → 232（-74%），随后 deref_after_alloc 降级 → **180（-80%）**；已知漏洞全保留。

---

## 三、v3 可达性标注（2026-08-22 上午）

### 动因
具身智能漏洞"默认可达 vs 配置后可达"差异巨大（XR 默认 0.0.0.0 vs AGIBOT 需配置 ros2 订阅）——上报时夸大可达性会损害可信度。

### 交付
- `cwe_reach.py`：5 组件默认可达性规则表（default/config/local/model-file）；
- **agibot 组件实时读 YAML**（`sub_topics_options`）作为证据；
- 端到端：detect(X1-9 JSON) → reach 标注 `config-reachable`（与攻击面调研一致）。

---

## 四、v4 CWE-248 扩展 + 覆盖度分析（2026-08-22 上午）

### 动因
覆盖度分析显示逻辑类（CWE-248 未捕获异常）不在工具域。

### 交付
- detect/repair 新增 CWE-248（`.at()` → `find()` 模板），命中 X1-8 L113；
- `coverage_analysis.py`：对 34-finding 数据集统计覆盖度；
- **覆盖度**：全自动闭环 23/34（67%）——AimRT 4/4、AGIBOT 12/14、NCNN 5/7；未覆盖=逻辑类（CWE-306/502/78，需不同模板）。

---

## 五、v5 真实 NCNN 二进制验证（2026-08-22 下午）

### 动因
模拟测试通过≠真实有效。**必须用真实二进制证明 verify 有效**。

### 过程（关键踩坑，全部修正）
1. **WSL hypervisor 关闭**（用户为三角洲行动禁用）→ WSL 不可用，验证推迟；
2. 恢复 WSL（bcdedit + VirtualMachinePlatform）后，用 08-12/08-15 的旧二进制（`loadpoc_file_vuln`/`loadpoc_file_fixed2`）；
3. **真实语义差异发现**：
   - `ret=-1` 输出在 **stderr**（仅捕 stdout 漏判）→ 合并捕获；
   - 进程被信号终止时 returncode 是**负信号码**（-11=SIGSEGV/-6=SIGABRT）→ crashed 判定含负值；
   - "合法输入"须用**同版本格式兼容**样本（squeezenet 旧格式报 "param is too old" 非误拒）→ 测试集修正。

### 最终结果
```
漏洞版（未修复）：恶意 149B → SIGSEGV(-11)、negidx → SIGABRT(-6) → REVIEW ✅
修复版（已修复）：恶意 → ret=-1 拒绝、合法 valid_minimal → ret=0 → PASS ✅
```

### 教训
**真实环境验证暴露了模拟测试不可能暴露的语义差异**——这是"修复必须真实验证"的最佳论据。

---

## 六、同类工具调研 + 差异化确认（2026-08-22 下午）

### 调研（子代理，25+ 仓库 GitHub API 核验）
报告：`研究文档/cwe-repair同类工具调研-2026-08-22.md`

### 关键结论
| 问题 | 结论 |
|---|---|
| 三合一闭环工具 | 存在（Copilot Autofix/CodeMender/PatchAgent），但验证全是"回归+人工审阅"，无攻击输入对抗验证 |
| 对称性检查 | **无任何同类**——`symmetry_check.py` 独有 |
| 双向回归验证 | **无补丁级现成工具**——`cwe_verify.py` 唯一成型 |
| 误报控制 | 各家用数据流/符号执行/LLM；cwe-repair 用"模板+守卫上下文+可达性+双向验证"组合 |

### 借鉴落地
1. **Semgrep 规则镜像**（`semgrep/cwe-repair-rules.yml`，7 条）——白嫖 test-ok/test-evil 生态；
2. **fuzz 验证输入自动扩充**（`fuzz_input_extractor.py`）——从 crash 目录自动提取恶意集，WSL 实测 5 恶意+1 合法 → verify PASS；
3. **发现 fuzz corpus 不适合当合法输入**（畸形为主）→ 修正为 `--benign-dir` 真实模型目录。

---

## 七、对称性检查（symmetry_check，防 bot 迭代）

### 动因（用户指出的痛点）
ncnn PR #6922 被 Codex bot 打回 2 次 P1：
1. **P1@net.cpp:31**：资源上限只加 text 路径，bin 路径（load_param_bin）没应用；
2. **P1@net.cpp:1406**：`top_count==0` 除零守卫不完整（text/bin 两处）。

共同根因 = **修复不对称**（同一校验只打了一个入口）。

### 交付与验证
- `symmetry_check.py`：成对入口（load_param/load_param_bin、WriteMember/WriteMemberNested）守卫对称性；
- **三场景实测**：
  | 场景 | 结果 |
  |---|---|
  | A（模拟 PR 第一版，只修 text） | ⚠️ `不对称: load_param 有守卫, 但 load_param_bin 没有` ✅ |
  | C（完整修复版 408f6df） | ✅ 对称良好（无误报） |
  | AimRT json_convert（真实 AR-1） | ⚠️ 不对称（WriteMember 有 / WriteMemberNested 无） ✅ |
- **结论**：修复后先跑 symmetry_check 自查兄弟路径，**提交前一步发现 bot 会打回的问题**。

### 踩坑记录
- find_functions 误提取调用语句（`WriteMemberNested(...)` 调用被当定义）→ 排除 `;`/`=`/缩进深行；
- 注释行 `// Handle sequences(...)` 被误判函数 → 排除 `//`；
- 类成员函数 `Net::load_param` 提取 → 正则支持 `ClassName::method`；
- 守卫检测：`bottom_count` 变量声明被当守卫 → 改用"校验语句"特征（`invalid bottom_count`/比较符）；
- `size() > array_size_` 的 `>` 在 array_size_ 前 → 正则兼容两种写法。

---

## 八、外部组件可行性验证（MNN/TNN）

### 8.1 MNN ground-truth 命中（issue #3595）
- 已知漏洞：`FileLoader::read(char*, int64_t)` 的 `fread(buffer,1,size,file)` size 无校验（2025-06 上报）；
- **工具命中 `FileLoader.cpp:173`**（read_size_unchecked + alloc_then_read）✅；
- **附加发现**：漏洞在最新 master 仍未修复（维护者"will fix later"后 stale）；
- **模式库扩展**：新增 `read_size_unchecked`（I/O 大小参数）模式——外部验证驱动模式扩展。

### 8.2 新缺陷发现：MNN FileLoader::merge 截断
- `buffer.reset((int)mTotalSize)`：size_t→int 截断 + memcpy 按未截断 offset → **>2GB 越界写候选**；
- 人工核验标注"潜在缺陷候选"（待大文件验证）。

### 8.3 误报评估（TNN RawBuffer）
- `memcpy(buff_.get(), buffer, bytes_size)`：构造参数自洽 → **安全（误报）**；
- 新增"自洽构造参数豁免"规则（同窗口 `new char[size]`/常量 → 过滤）——TNN 误报清除、MNN 真实漏洞保留。

### 结论
工具能在全新组件检出已知漏洞（ground-truth）、标出潜在新缺陷、并明确区分需人工核验的候选；误报率中等，须配合"人工/agent 核验"环节。

---

## 九、v6 漏洞驱动的工具迭代（截断模式）

### 动因
MNN 扫描发现 `merge` 截断漏洞 → 现有模式库无"截断"类别。

### 迭代
- **detect 新增 `size_truncation`**：`(int)size_t` 显式截断（MNN FileLoader::merge L130 驱动）；
- **repair 新增 `190_trunc` 模板**：截断前校验 `src > INT_MAX` 则拒绝，再安全转换；
- 完整闭环：MNN 扫描 → 发现截断 → 扩展模式 → 生成鲁棒补丁 → 回归全过。

---

## 十、外部组件负面结果对照（ORT/Paddle-Lite）

| 组件 | 校验成熟度 | cwe-repair 发现 |
|---|---|---|
| onnxruntime v1.28.0（WSL 本地克隆） | 高（维度/溢出/负数全查） | 无新漏洞（负面） |
| Paddle-Lite（gitee 镜像） | 中高（CHECK 断言） | 无新漏洞（负面） |
| MNN master | 中（FileLoader/Interpreter 有缺口） | ✅ 2 处截断漏洞 |
| agibot_x1_infer / xr_teleoperate | 低（无维护/Python 无认证） | ✅ 高产出 |

**实证结论**：工具在"已加固大厂解析器"无误报过多，在"未加固中小组件"高产出 → **扫描优先级 = 低维护/无安全流程组件**（论文可写"目标选择方法论"）。

---

## 十一、v7 leaderboard 基准化 + 跨行匹配（2026-08-22 晚）

### 动因
需要"防回归 + 量化"的基准（RepairBench 思路）。

### 交付
- `cwe_leaderboard.py`：对 34-finding 数据集跑 detect，输出检出率基准；
- **基准驱动迭代**（关键）：
  | 迭代 | 检出率 | 暴露问题 |
  |---|---|---|
  | 初版 | 32%（10/31） | `parallel_array_loop` 单行无法跨 for 头（X1-4 不可检） |
  | +跨行匹配 | 38%（12/31） | detect 架构改进：跨行模式用前 6 行窗口 |
  | +CWE 同族 | **48%（15/31）** | AR-1（数据集 787 vs detect 125）匹配 |

- **同时发现**：MNN `Interpreter::createFromBuffer`（L107 `(int)size` 截断 + 按原 size memcpy）——**第二处未公开截断漏洞，公开 API 入口**（Interpreter.hpp:120），已生成鲁棒补丁 + 分析文档。

### 工具架构改进
- detect 单行扫描 → **跨行窗口匹配**（parallel_array_loop/alloc_then_read 用前 6 行）；
- 注释/#include/纯字符串行全局过滤（ORT 扫描发现的注释误报）；
- leaderboard 匹配逻辑：basename 精确匹配 + CWE 同族（125/787）。

---

## 十二、最终交付物清单（v7 终态）

### 工具（9 脚本 + Semgrep 规则）
```
.dsh/skills/cwe-repair/
├── SKILL.md / README.md
├── scripts/
│   ├── cwe_reach.py             # 可达性标注（5 组件 + YAML 实测）
│   ├── cwe_detect.py            # 检测（12+ 模式，跨行，误报 -80%）
│   ├── symmetry_check.py        # 成对入口对称性（独有，防 bot 迭代）
│   ├── cwe_repair.py            # 鲁棒性修复模板（7 类含截断）
│   ├── cwe_verify.py            # 双向验证（真实 PASS/REVIEW）
│   ├── coverage_analysis.py     # 覆盖度分析
│   ├── cwe_leaderboard.py       # 检测基准化（防回归，48% 检出）
│   └── fuzz_input_extractor.py  # fuzz 验证输入自动扩充
├── semgrep/cwe-repair-rules.yml # Semgrep 规则镜像（7 条）
└── examples/ncnn_blobidx_verify.json
```

### 研究文档
- `研究文档/cwe-repair同类工具调研-2026-08-22.md`（25+ 仓库差异化确认）
- `研究文档/cwe-repair外部组件可行性验证-2026-08-22.md`（MNN/TNN ground-truth）
- `研究文档/cwe-repair迭代与验证总结-2026-08-22.md`（每轮总结）
- `研究文档/embodied-ai-cwe-dataset.json`（34 findings 数据集）
- `研究文档/具身智能垂直领域评估-cwe-repair-2026-08-22.md`
- `TOOLTEST_MNN/MNN-Interpreter截断漏洞-2026-08-22.md`（新漏洞分析）
- `TOOLTEST_ORT/onnxruntime扫描分析-2026-08-22.md`、`TOOLTEST_PADDLE/Paddle-Lite扫描分析-2026-08-22.md`（负面结果）

### 可 PR 补丁
- `AGIBOT/上报材料/fix-x1_infer-jointcmd-parallel-array.patch`（X1-4，git apply 验证）
- `AGIBOT/上报材料/fix-x1_infer-writemotorcmd-oob.patch`（X1-5，git apply 验证）
- `AGIBOT/上报材料/X1-4-JointCmd平行数组-修复PR材料-2026-08-22.md`（commit message + 证据）

---

## 十三、方法论沉淀（跨迭代）

1. **漏洞驱动的工具迭代**：真实扫描发现的漏洞形态 → 扩展模式库 → 生成对应修复模板 → 回归验证——工具随目标演进（v6 截断、v7 跨行均由扫描驱动）；
2. **基准量化驱动改进**：leaderboard 暴露的检出缺口 → 针对性迭代（跨行/CWE 同族）→ 32%→48%；
3. **真实环境验证不可替代**：exit code vs ret 输出 vs 信号码的语义差异，模拟测试永远发现不了；
4. **负面结果有价值**：ORT/Paddle-Lite 无新漏洞 = "目标已加固"的实证，指引扫描优先级；
5. **诚实边界**：detect 是"初筛器"非"精确扫描器"（48% 检出 = 需 agent/人工核验）；对称性/双向验证是独有差异化；逻辑类（CWE-306/502/78）仍需不同模板。

---

## 十四、下一步候选（未执行，待用户决策）

1. **MNN Interpreter 截断漏洞完整上报材料**（含 PR 补丁 + GHSA 建议）；
2. **提升 leaderboard 检出率**（X1-1/3/7/11-14 等 MISS 项的模式扩展）；
3. **34-finding leaderboard 结果做成防回归 CI**（RepairBench 式）；
4. **更多组件扫描**（FastDeploy/unitree_sdk2py，需 gitee 或本地源码）。
