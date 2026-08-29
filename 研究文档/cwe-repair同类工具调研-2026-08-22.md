# cwe-repair 同类工具调研报告：自动化漏洞检测 + 修复补丁生成 + 修复正确性验证闭环

> 调研人：安全工具生态调研员　|　调研时间：2026-02（star 数/许可证均通过 GitHub REST API 实时核验，未核实项标注"待核验"）
> 基线工具：cwe-repair（DSH skill，5 个 Python 脚本：`cwe_detect.py` 规则模板检测、`symmetry_check.py` 成对入口对称性检查、`cwe_repair.py` 模板化补丁、`cwe_verify.py` 双向回归验证、`coverage_analysis.py` 覆盖度分析）

---

## 0. 结论先行（TL;DR）

1. **"检测+修复+验证"三合一闭环的工具存在**：Copilot Autofix（CodeQL 检测 → Copilot 修复 → CI 验证）、Google CodeMender（闭源）、PatchAgent（USENIX Sec'25）、VulnFix（模糊测试驱动）。但它们的"验证"几乎全部是**现有测试套件的回归 + 人工审阅**，没有一家做"攻击输入必须被拒 + 合法输入必须不误拒"的双向对抗验证。
2. **对称性检查（成对入口修复不对称检测）没有任何现成工具**。最接近的学术方向是补丁移植/克隆补丁一致性（PaReco、克隆补丁切片），但都不是"text/bin 双解析器、兄弟函数"这种成对入口的自动对称性检查——**cwe-repair 独有**。
3. **恶意拒绝 + 良性不误拒的双向回归验证没有现成工具**。最接近的类比是 Semgrep 规则的 `test-ok`/`test-evil`（但那是规则级测试，不是补丁级）；Poracle 只覆盖"行为保持（不误伤）"单向；OSS-Fuzz 回归只覆盖"崩溃不复现（恶意方向）"单向。**`cwe_verify.py` 的双向设计是差异化核心**。
4. **误报率控制策略**各家不同：数据流/污点追踪（CodeQL、Semgrep taint）、值流/符号执行（cppcheck）、路径敏感+污点（Clang Static Analyzer）、过程间分析（Infer）、LLM 上下文判别 + 测试验证（Copilot Autofix、CodeMender、PatchAgent）。cwe-repair 的组合是：模式模板 + 上下文守卫检查 + 可达性标注 + 双向验证。
5. **cwe-repair 真正的差异化**：轻量、确定性、可审阅（非 LLM 黑盒）、双向验证、对称性检查、具身智能垂直领域（可达性标注）。短板在检测精度（纯语法模式）和验证输入覆盖面（人工 PoC）。

---

## 1. 静态分析工具（检测侧）

| 项目 | GitHub | Star | 许可证 | 核心功能 | 与 cwe-repair 重叠/差异 | 值得借鉴 |
|---|---|---|---|---|---|---|
| CodeQL | [github/codeql](https://github.com/github/codeql) | 9,997 | MIT | QL 声明式查询语言；数据流/污点追踪库；CWE 映射（[CWE 覆盖文档](https://docs.github.com/zh/code-security/codeql/codeql-for-code-scanning)）；GitHub Code Scanning 与 Copilot Autofix 的检测底座 | 检测能力远超规则模板（精确数据流）；但**无修复、无双向验证**，查询编写门槛高 | 用 CodeQL 数据流查询校验 cwe-repair 模板命中的"下标确实来自攻击者输入"（替代手工上下文判断） |
| cppcheck | [danmar/cppcheck](https://github.com/danmar/cppcheck) | 6,726 | GPL-3.0 | 值流/符号执行分析；低误报（只报有把握的问题）；XML 输出带 CWE ID；支持 MISRA 插件 | 覆盖 CWE-125/787/190/369/476 等（越界/溢出/除零/空指针），与 cwe-repair 目标 CWE 高度重叠；无修复/验证 | 借鉴其**值流分析**：模板命中后自动检查下标是否被守卫过滤，降低误报 |
| Clang Static Analyzer | [llvm/llvm-project](https://github.com/llvm/llvm-project)（clang 内） | 39,881 | Apache-2.0（LLVM 发行） | 路径敏感分析；`alpha.security.*` 检查器、taint 配置（[Taint Analysis 文档](http://releases-origin.llvm.org/18.1.8/tools/clang/docs/analyzer/user-docs/TaintAnalysisConfiguration.html)） | 路径敏感可精确判定"越界是否可达"；alpha 检查器默认关闭、误报不稳定；无修复 | taint 配置思路可借鉴：给 cwe-repair 模板加"污点源=攻击者输入"维度 |
| Semgrep | [semgrep/semgrep](https://github.com/semgrep/semgrep) | 16,358 | LGPL-2.1 | 类源码模式匹配；`taint-mode` 数据流；**规则内嵌 `fix:` 自动修复**；**规则测试 `test-ok`/`test-evil`**（[测试规则文档](https://semgrep.dev/docs/writing-rules/testing-rules)）；规则注册表带 CWE 标签 | 与 cwe-repair 最"同构"：模板式检测 + 自动补丁 + 正反例测试。但 autofix 是文本替换、验证是规则级而非运行级 | **`test-ok`/`test-evil` 即 cwe-repair 双向验证的规则级版本**；建议把 cwe-repair 规则迁移/镜像为 Semgrep 规则以白嫖生态 |
| Infer | [facebook/infer](https://github.com/facebook/infer) | 15,684 | MIT | 分离逻辑/过程间分析；空指针、泄漏、并发；假阳性少 | 补检测盲区（空指针/泄漏），但非安全 CWE 导向 | 无 |
| flawfinder | [david-a-wheeler/flawfinder](https://github.com/david-a-wheeler/flawfinder) | 581 | GPL-2.0 | 词法扫描 + 风险权重评分；输出映射 CWE/CVE | 与 cwe-repair 同为"规则+权重"，但纯词法、误报高、无上下文 | 风险评分机制可借鉴（cwe-repair 目前无风险分级） |
| GitHub Security Lab | [github/securitylab](https://github.com/github/securitylab) | 1,624 | MIT | CodeQL 查询资源、CTF、研究用例 | 查询库资源 | 可引用其 C/C++ 安全查询模板 |

---

## 2. 自动化程序修复（APR）工具（修复侧）

| 项目 | 地址 | Star | 许可证 | 核心功能 | 补丁验证机制 | 与 cwe-repair 差异 |
|---|---|---|---|---|---|---|
| GenProg | 原仓库 [squaresLab/GenProg](https://repos.ecosyste.ms/hosts/GitHub/owners/squaresLab) 已 404（移除，**待核验**）；可用 fork [genprog-code-hufork](https://github.com/xinzhuohuZJU/genprog-code-hufork)；Java 版 [genprog4java](https://github.com/squaresLab/genprog4java)（18★） | 0~18 | 待核验 | 遗传编程搜索补丁空间（删除/插入/替换语句），APR 鼻祖 | **回归测试**（fail-to-pass + pass-to-pass） | 随机搜索 + 仅测试验证 → 过度拟合问题（催生了 Poracle 等研究）；cwe-repair 是确定性模板，无随机性 |
| RepairBench + framework | [ASSERT-KTH/repairbench](https://github.com/ASSERT-KTH/repairbench)（11★）、[repairbench-framework](https://github.com/ASSERT-KTH/repairbench-framework)（22★） | 11/22 | 待核验 | LLM 修复的公开基准/排行榜（[论文 arXiv 2409.18952](https://arxiv.org/abs/2409.18952)，Silva & Monperrus）；框架支持 Defects4J、GitBug-Java、HumanEval-Java、QuixBugs、RunBugRun；数据集含数千真实 bug（**精确数量待核验**） | 标准测试套件回归（fail-to-pass/pass-to-pass 判定） | 纯基准，不生产补丁到真实项目；cwe-repair 的 `coverage_analysis.py` 可借鉴其 leaderboard/基准化思路 |
| CodeMender | 闭源商业（[DeepMind 博客](https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/)） | — | 闭源 | Google DeepMind（2025-10）AI agent：检测→修复→验证闭环；官方称 6 个月修复 72 个 OSS 漏洞（[报道](https://scalebytech.com/google-deepminds-codemender-automates-vulnerability-fixes-patches-72-open-source-flaws-in-six-months)） | 沙箱内构建 + 测试验证修复（"verifying fixes" 是其卖点之一，[对比分析](https://www.orcarouter.ai/blog/codemender-vs-prime-agent)）；细节未公开 | 黑盒 LLM、不可审阅；验证仍是回归式；cwe-repair 的确定性补丁 + 显式双向验证与之形成对照 |
| Copilot Autofix | GitHub 商业（[官方文档](https://docs.github.com/zh/code-security/concepts/code-scanning/autofix-for-code-scanning)） | — | 闭源 | CodeQL 检测 → Copilot 生成 PR 补丁 → 自动跑 CI + 人工审阅；2026 推出 agentic autofix（[changelog](https://github.blog/changelog/2026-07-10-agentic-autofix-for-code-scanning-alerts-in-public-preview/)） | CI 测试 + PR 审阅；局限：依赖现有测试覆盖、无对抗输入验证（[How It Works & Its Limits](https://safeguard.sh/resources/blog/how-copilot-autofix-generates-ai-powered-vulnerability-fixes-in-code-scanning/)） | 三合一闭环最完整的产品化形态；但验证维度单一 |
| PatchAgent | [cla7aye15I4nd/PatchAgent](https://github.com/cla7aye15I4nd/PatchAgent) | 127 | Apache-2.0 | USENIX Security '25（[论文](https://www.usenix.org/conference/usenixsecurity25/presentation/yu-zheng)）：LLM agent 模仿人类专家，规划→定位→修复，多工具协作 | 多工具交叉验证：静态分析 + 构建 + 回归测试 | 验证强调"工具链交叉"，值得借鉴其 patch validation 管线设计 |
| RepairAgent | [sola-st/RepairAgent](https://github.com/sola-st/RepairAgent) | 106 | 待核验（无 license 文件） | 自主 LLM agent + 预定义工具 API（编译/测试/编辑），ICLR 2025 | 回归测试 + 迭代工具调用 | 工具化 agent 范式 |
| VulnFix | [yuntongzhang/vulnfix](https://github.com/yuntongzhang/vulnfix) | 21 | GPL-3.0 | **模糊测试驱动的漏洞修复**（归纳推理，ISSTA'22）：用 crash 复现 + 测试约束引导补丁生成，基于 Angelix | 回归测试 + crash 复现测试 | 与 cwe-repair 思路互补：cwe-repair 人工提供 PoC，VulnFix 靠 fuzz 自动找 PoC |

---

## 3. 漏洞验证 / 补丁正确性评估（验证侧）

| 项目 | 地址 | Star | 许可证 | 核心功能 | 与 cwe-repair 重叠/差异 |
|---|---|---|---|---|---|
| Poracle | [poracle100/poracle-experiments](https://github.com/poracle100/poracle-experiments)（0★，论文 [TOSEM](https://dl.acm.org/doi/full/10.1145/3625293)） | 0 | 待核验 | 在"preservation conditions"（行为保持条件）下测试补丁，用 delta debugging 最小化测试，对抗**补丁过度拟合** | 只验证"原行为不回归"（对应 cwe-repair B 方向）；**无恶意拒绝方向**。delta debugging 最小化输入值得借鉴 |
| Invalidator | [thanhlecongg/Invalidator](https://github.com/thanhlecongg/Invalidator) | 7 | MIT | 语义+句法推理判定补丁正确性（IEEE TSE） | 给补丁"打分"而非跑输入；可作 cwe-repair 补丁生成后的第二道质检 |
| Shibboleth | [ali-ghanbari/shibboleth](https://github.com/ali-ghanbari/shibboleth) | 8 | Apache-2.0 | 基于补丁对生产/测试代码影响面的补丁正确性评估 | 影响面分析思路可用于 symmetry 检查（补丁影响面不对称检测） |
| LLM-Oracle | [inyeongjang/LLM-Oracle](https://github.com/inyeongjang/LLM-Oracle) | 0 | MIT | LLM 作为补丁正确性 oracle（ICST 2026） | LLM 判别可作为 cwe-repair 验证前的预筛 |
| FURINA | [YuningLi0902/furina](https://github.com/YuningLi0902/furina) | 0 | 待核验 | 多 agent 框架做补丁正确性评估 | agent 化评估范式 |
| DL4PatchCorrectness | [TruX-DTF/DL4PatchCorrectness](https://github.com/TruX-DTF/DL4PatchCorrectness) | 15 | 待核验 | 补丁正确性经验研究/数据集（含 PatchCorrectness 数据集，artifact 另见 [claudeyj/patch_correctness](https://github.com/claudeyj/patch_correctness)） | 数据集可作 cwe-repair 验证器的基准语料 |
| 回归测试工具链 | 各 CI（GitHub Actions 等） | — | — | 通用 fail-to-pass/pass-to-pass 回归 | 单向（无攻击输入）；是 cwe-repair B 方向的通用实现 |
| diff-based 验证 | 无独立主流工具（内嵌于 PR review / patch 分析） | — | — | 对补丁做静态 diff 审查 | cwe-repair 的 `--out fix.patch` + 人工审阅同思路 |

---

## 4. 安全领域的 agent / skill 包

| 项目 | 地址 | Star | 许可证 | 核心功能 | 与 cwe-repair 差异 |
|---|---|---|---|---|---|
| anthropics/skills | [anthropics/skills](https://github.com/anthropics/skills) | 171,083 | 未标注（**待核验**） | Anthropic Agent Skills 官方仓库；含部分安全类 skill；社区有对 security skill 信任边界的讨论（[issue #492](https://github.com/anthropics/skills/issues/492)） | 生态/分发标准，无检测-修复-验证闭环 |
| Anthropic-Cybersecurity-Skills | [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 30,714 | Apache-2.0 | 817 个结构化网络安全技能，映射 MITRE ATT&CK / NIST CSF 2.0 / ATLAS / D3FEND 等 6 框架，适配 Claude Code / Copilot / Codex CLI 等 20+ 平台 | 技能覆盖面广但都是"指令包"，**不执行检测/补丁/验证**；cwe-repair 是带脚本执行的闭环 skill，定位互补 |
| claude-security-skills | [Dolphinllc/claude-security-skills](https://github.com/Dolphinllc/claude-security-skills)（1★）、[ez-lbz/claude-code-security-skills](https://github.com/ez-lbz/claude-code-security-skills)（23★） | 1/23 | MIT/待核验 | Claude Code 防御侧安全技能（Web 应用、生成式 AI 系统） | 同上有指令无闭环 |
| dsh-skill-pack-security | [PerryLink/dsh-skill-pack-security](https://github.com/PerryLink/dsh-skill-pack-security) | 3 | Apache-2.0 | DSH 安全审计技能包：8 个双语 agent 技能（secret scan、依赖审计、供应链审查、prompt 注入审查、审计编排、威胁建模、漏洞情报、应急响应）+ plugin_vet 供应链门禁 | **DSH 生态中与 cwe-repair 最接近的同类**，但偏"审计/门禁"，无补丁生成与运行级双向验证 |
| dsh-plugin-cyber | [Vme18000yuan/dsh-plugin-cyber](https://github.com/Vme18000yuan/dsh-plugin-cyber)（3★，[FreeBuf 发布文](https://www.freebuf.com/articles/sectool/496337.html)） | 3 | Apache-2.0 | DSH 安全测试工作流插件 | 偏渗透/测试工作流，非防御性修复闭环 |
| dsh-guardwall | [iiiweiii/dsh-guardwall](https://github.com/iiiweiii/dsh-guardwall) | 0 | MIT | DSH 运行时安全护栏：拦截危险工具输入、输出泄漏审计、HMAC 审计日志 | 运行时防护，非漏洞修复 |
| awesome-dsh-plugin | [beancookie/awesome-dsh-plugin](https://github.com/beancookie/awesome-dsh-plugin)（103★）、[fendouai/awesome-deepseek-harness](https://github.com/fendouai/awesome-deepseek-harness)（18★） | 103/18 | CC0-1.0/MIT | DSH 插件/生态索引 | 可作分发渠道 |

---

## 5. 模糊测试验证（验证侧补充）

| 项目 | 地址 | Star | 许可证 | 核心功能 | 与 cwe-repair 的关系 |
|---|---|---|---|---|---|
| OSS-Fuzz | [google/oss-fuzz](https://github.com/google/oss-fuzz) | 12,572 | Apache-2.0 | 开源软件持续模糊测试；**crash 复现 → 修复 → 回归测试** 的标准工作流（[复现文档](https://android.googlesource.com/platform/external/oss-fuzz/+/9848e9e4fdb3c6f05722b658b0ad43fdd0fd5b52/docs/reproducing.md)） | 其"回归 = 崩溃不再复现"是**恶意方向的单向验证**；cwe-repair 补充了良性方向。fuzz 发现的 PoC 可直接喂给 `cwe_verify.py --malicious` |
| ClusterFuzz | [google/clusterfuzz](https://github.com/google/clusterfuzz) | 5,592 | Apache-2.0 | 可扩展模糊测试基础设施（调度/去重/复现） | 提供 PoC 生产管线 |
| oss-fuzz-gen | [google/oss-fuzz-gen](https://github.com/google/oss-fuzz-gen) | 1,431 | Apache-2.0 | LLM 生成/改进 fuzz target（覆盖引导） | 可借鉴：用 LLM 自动扩充 cwe-repair 的恶意输入集 |
| FuzzRepair（论文） | 工具仓库未公开检索到（**待核验**；论文 [Program Repair by Fuzzing over Patch and Input Space](https://arxiv.org/abs/2308.00666)，USENIX Sec'23，作者 Zhang & Shariffdeen 等） | — | — | 同时在"补丁空间 + 输入空间"做 fuzzing，把补丁当变异目标 | 思路上与 cwe-repair 互补：cwe-repair 固定补丁模板验证输入，它固定输入探索补丁空间 |

---

## 6. 五个重点问题的回答

### Q1：有没有工具同时做"检测+修复+验证"三件事并形成闭环？
**有，但"验证"的深度不足。**
- 产品化闭环：**Copilot Autofix**（CodeQL→Copilot→CI+PR）、**CodeMender**（闭源，检测→修复→沙箱验证）、**PatchAgent/RepairAgent**（agent 内多工具交叉验证）。
- 研究型闭环：**VulnFix**（fuzz 复现→归纳修复→回归）。
- 共同短板：验证 = 现有测试套件回归 + 人工审阅，**没有针对攻击输入的对抗验证**，也没有"不误伤合法输入"的系统化断言（除 Poracle 单向研究）。→ cwe-repair 的三合一闭环在"验证质量"上反而更完整。

### Q2：有没有工具做"对称性检查"（成对入口修复不对称检测）？
**没有直接同类。**
- 最近邻是"补丁一致性/移植"研究：**PaReco**（[unlv-evol/PaReco](https://github.com/unlv-evol/PaReco)，软件家族变体间缺失补丁检测）、[Slicing-Based Vulnerable Code Clone Patching](https://ar5iv.labs.arxiv.org/html/2505.02349)、[Mitigating Implicit Inconsistencies in Patch Porting](https://www.emergentmind.com/papers/2604.01680)——都是"克隆代码补丁同步"，不是"成对入口函数（text/bin 双解析器、WriteMember/WriteMemberNested 兄弟函数）的守卫对称性"。
- **cwe-repair 的 `symmetry_check.py` 在工具层面是独一份**，且直接针对 ncnn PR #6922 这类真实打回案例。

### Q3：有没有工具做"恶意输入拒绝 + 合法输入不误拒"的双向回归验证？
**没有补丁级的现成工具。**
- 规则级最接近：**Semgrep 的 `test-ok`/`test-evil`**（规则的正反例测试）——但那是检测规则的质量测试，不是修复补丁的运行级验证。
- 单向验证到处都是：OSS-Fuzz 回归（恶意方向）、Poracle preservation conditions（良性方向，学术实验）。
- **`cwe_verify.py` 的双向运行级验证（ret=-1 拒绝 + ret=0 不误拒）是目前唯一成型的补丁级双向回归设计**，且输出 `PASS/REVIEW` 三元组可直接进 PR/报告。

### Q4：误报率控制策略对比
| 策略 | 代表 | 说明 |
|---|---|---|
| 数据流/污点追踪 | CodeQL、Semgrep taint-mode | 精确追踪攻击者输入到达敏感点，精度高、成本高 |
| 值流/符号执行 | cppcheck | 只报有把握的问题，牺牲召回换精度 |
| 路径敏感 + 污点 | Clang Static Analyzer | alpha 检查器默认关闭，需显式启用 |
| 过程间分析 | Infer | 分离逻辑，假阳性少、漏报多 |
| 词法 + 风险权重 | flawfinder | 快但误报高，靠评分排序 |
| LLM 上下文判别 + 测试验证 | Copilot Autofix、CodeMender、PatchAgent | 语义理解去噪，用回归测试兜底 |
| **组合：模板 + 上下文守卫检查 + 可达性标注 + 双向验证** | **cwe-repair** | 模板命中后查同函数已有守卫则跳过；`cwe_reach.py` 区分默认/配置可达；双向验证兜底 |

### Q5：cwe-repair 的差异化与可借鉴改进
**差异化（相对所有同类）**：
1. **双向运行级验证**（`cwe_verify.py`）——无同类；把"修复正确性"从"测试通过"提升到"攻击被拒 + 功能不回归"。
2. **成对入口对称性检查**（`symmetry_check.py`）——无同类；直击 LLM 修复 agent（Codex 等）反复踩的坑（ncnn PR #6922 实证）。
3. **确定性模板补丁**（`cwe_repair.py`）——非 LLM 黑盒，一行检查可审阅、可审计，与 CodeMender/Copilot Autofix 的生成式补丁形成对照。
4. **垂直领域可达性标注**（`cwe_reach.py`）——具身智能组件（ncnn/mindspore/agibot/aimrt/xr）默认可达 vs 配置可达，避免夸大/低估漏洞。
5. **完整证据三元组**（检测 N / 补丁 M / 验证 PASS）——可直接嵌入 PR body，这是其他工具没有的"可交付闭环"。

**可借鉴的改进点（按优先级）**：
1. **验证输入自动扩充**：接入 libFuzzer/oss-fuzz-gen，用 LLM 自动生成恶意输入集喂给 `cwe_verify --malicious`（借鉴 [oss-fuzz-gen](https://github.com/google/oss-fuzz-gen)）；用 delta debugging 最小化 PoC（借鉴 [Poracle](https://dl.acm.org/doi/full/10.1145/3625293)）。
2. **检测精度升级**：对模板命中做 CodeQL 数据流校验（下标确来自攻击者输入）或借鉴 Semgrep taint-mode，降低人工确认负担。
3. **补丁二道质检**：接入 Invalidator/Shibboleth 式语义推理对补丁打分；用 LLM-Oracle 做预筛。
4. **对称性检查自动化扩展**：借鉴 PaReco 的克隆检测自动发现"成对入口"，目前 `symmetry_check` 依赖人工指定兄弟函数。
5. **规则生态化**：将模板镜像为 Semgrep 规则（白嫖 `test-ok`/`test-evil` 框架 + 社区），cwe-repair 保留运行级验证差异层。
6. **基准化**：仿 RepairBench 把 34-finding 数据集做成 leaderboard，`coverage_analysis.py` 输出可对比基线（防回归）。
7. **CI 集成与分发**：输出 GitHub Actions action + 安全公告格式（OSV），进 awesome-dsh-plugin 生态。

---

## 7. 对比总表（一行一工具）

| 工具 | 检测 | 修复 | 验证 | 验证方式 | 对称性检查 | 双向验证 | 闭源/开源 |
|---|---|---|---|---|---|---|---|
| **cwe-repair** | ✅ 模板 | ✅ 模板化 | ✅ | **运行级双向（恶意拒绝+良性不误拒）** | ✅ **独有** | ✅ | 开源（DSH skill） |
| CodeQL | ✅ 数据流 | ❌ | ❌ | — | ❌ | ❌ | 开源(查询) |
| cppcheck | ✅ 值流 | ❌ | ❌ | — | ❌ | ❌ | GPL-3.0 |
| Clang SA | ✅ 路径敏感 | ❌ | ❌ | — | ❌ | ❌ | 开源 |
| Semgrep | ✅ 模式+taint | ✅ autofix | ⚠️ 规则级 | test-ok/test-evil | ❌ | ⚠️ 规则级 | LGPL-2.1 |
| Infer | ✅ 过程间 | ❌ | ❌ | — | ❌ | ❌ | MIT |
| flawfinder | ✅ 词法 | ❌ | ❌ | — | ❌ | ❌ | GPL-2.0 |
| GenProg | ❌ | ✅ 遗传搜索 | ⚠️ | 回归测试 | ❌ | ❌ | 待核验 |
| RepairBench | ❌(基准) | ✅(评测) | ⚠️ | 回归测试 | ❌ | ❌ | 开源 |
| CodeMender | ✅ | ✅ | ✅ | 沙箱回归(未公开) | ❌ | ❌ | 闭源 |
| Copilot Autofix | ✅ CodeQL | ✅ Copilot | ✅ | CI+PR 审阅 | ❌ | ❌ | 闭源 |
| PatchAgent | ✅ | ✅ | ✅ | 多工具+回归 | ❌ | ❌ | Apache-2.0 |
| RepairAgent | ✅ | ✅ | ✅ | 工具迭代+回归 | ❌ | ❌ | 待核验 |
| VulnFix | ✅ fuzz | ✅ 归纳 | ✅ | 回归+crash | ❌ | ❌ | GPL-3.0 |
| Poracle | ❌ | ❌ | ✅ | 行为保持(单/良向) | ❌ | ❌(单/良向) | 开源 |
| Invalidator/Shibboleth/LLM-Oracle | ❌ | ❌ | ✅ | 语义推理/LLM oracle | ❌ | ❌ | MIT/Apache |
| OSS-Fuzz | ✅ fuzz | ❌(人工) | ✅ | crash 回归(单/恶向) | ❌ | ❌(单/恶向) | Apache-2.0 |
| dsh-skill-pack-security | ⚠️ 审计 | ❌ | ❌ | — | ❌ | ❌ | Apache-2.0 |
| Anthropic-Cybersecurity-Skills | ❌(指令) | ❌ | ❌ | — | ❌ | ❌ | Apache-2.0 |

---

## 8. 附：数据说明
- Star 数/许可证为 2026-02 通过 `api.github.com` 实时核验；标注"待核验"项：GenProg 原仓库（已 404，确认移除但原 star 数不可考）、RepairBench 数据集精确 bug 数、RepairAgent/anthropics/skills/DL4PatchCorrectness 许可证、FuzzRepair 工具仓库（论文 [arXiv 2308.00666](https://arxiv.org/abs/2308.00666) 已公开，但未检索到同名开源仓库）。
- 商业闭源工具（CodeMender、Copilot Autofix）无 star 数，其能力描述基于官方文档与第三方评测报道。
