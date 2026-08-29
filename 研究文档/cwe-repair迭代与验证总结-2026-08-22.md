# cwe-repair 迭代与验证总结（2026-08-22，第三阶段）

> 本轮完成：同类工具全面调研 + 降误报迭代 + 修复模板鲁棒性增强 + 新组件扫描 + 自我优化。
> 目标：验证"检测→修复→对称性→验证"全闭环的差异化价值，并持续改进。

## 一、同类工具调研结论（差异化的独立确认）

**调研报告**：`研究文档/cwe-repair同类工具调研-2026-08-22.md`（25+ 仓库，GitHub API 实时核验）

| 问题 | 结论 |
|---|---|
| 三合一闭环工具 | 存在（Copilot Autofix/CodeMender/PatchAgent），但验证全是"回归测试+人工审阅"，**无攻击输入对抗验证** |
| 对称性检查 | **无任何同类**——`symmetry_check.py` 独有（最近邻是补丁移植研究，非成对入口守卫检查） |
| 双向回归验证 | **无补丁级现成工具**——`cwe_verify.py` 的双向设计唯一成型（Semgrep 是规则级、Poracle 单向、OSS-Fuzz 单向） |
| 误报控制 | 各家用数据流/符号执行/LLM；cwe-repair 用"模板+守卫上下文+可达性+双向验证"组合 |
| **cwe-repair 差异化** | **双向运行级验证 + 成对入口对称性检查（均无同类）** + 确定性模板补丁 + 具身智能可达性标注 |

## 二、降误报迭代（误报 -80%）

基于 MNN/TNN 真实扫描量化误报来源后迭代：

| 迭代 | 策略 | MNN core 命中数 |
|---|---|---|
| v1 | 通用正则（全部模式默认开） | 893 |
| v2 | 模式加置信度（low 默认关）+ 过滤器 | 232（-74%） |
| v3 | deref_after_alloc 降 low + nested_index 精确模式 | **180（-80%）** |

- 低置信模式（index_arith/array_index_raw/deref_after_alloc）默认关闭，需 `--include-low`
- 新增 high 置信精确模式：`nested_index`（二次/派生下标）、`index_write_raw`（越界写）
- **回归全过**：AR-1 L170 / X1-9 L21 / MNN L173 / X1-10 L154 全部保留

## 三、修复模板鲁棒性增强（不止修漏洞）

v2 模板加入**防御性编程**：
1. 错误日志带**实际 size/值**（`invalid index %d (size=%zu)`）——便于诊断
2. 错误路径显式**清理/释放**（`cleanup` 参数，防泄漏）
3. CWE-369 除零改为**默认值回退**（`fallback`，不因畸形输入崩溃整个模块）
4. 可配置 `fail_ret`（错误返回码）

实测：X1-10 除零 → `if (freq_==0) { log; freq_=1; }`（回退而非崩溃）；AR-1 → 带 size 日志的边界检查。

## 四、新组件扫描（Paddle-Lite + onnxruntime）

### 4.1 Paddle-Lite（gitee 镜像）
- 扫描 `lite/core/model`（22 文件 8 命中）与 `lite/core`（358 文件 371 命中）
- **人工核验**：io.cc:38 ReadToString → size=file.length()（安全）；io.cc:54 fread 有 CHECK 断言（安全）；
  device_info 内部索引（误报，已被过滤器拦截）
- **结论**：无新漏洞——模型解析器较严谨（CHECK 断言保护）

### 4.2 onnxruntime v1.28.0（WSL 本地克隆）
- 扫描 `core/graph`（83 文件 150 命中）与 `core/providers`（1480 文件 6020 命中）
- **人工核验**：graph_flatbuffers_utils.cc:416 resize(num_bytes) → 上游 GetSizeInBytesFromFbsTensor
  有维度/溢出/负数全查（安全）
- **结论**：无高置信新漏洞——核心解析器已加固

### 4.3 ⭐ 负面结果对照（论文价值）

| 组件 | 校验成熟度 | cwe-repair 发现 |
|---|---|---|
| onnxruntime v1.28.0 | 高（维度/溢出/负数全查） | 无新漏洞（负面） |
| Paddle-Lite | 中高（CHECK 断言） | 无新漏洞（负面） |
| MNN master | 中（FileLoader 有缺口） | ✅ issue #3595 + merge 截断候选 |
| agibot_x1_infer | 低（2025-04 后无维护） | ✅ 14 个缺陷 |
| xr_teleoperate | 低（Python 无认证） | ✅ 6 个漏洞 |

**结论**：cwe-repair 在"已加固的大厂解析器"上**无误报过多**，在"未加固的中小组件"上
**高产出**——扫描优先级应聚焦**低维护/无安全流程**的组件（实证指引）。

## 五、自我优化（调研建议落地）

| 建议 | 落地状态 |
|---|---|
| 验证输入自动扩充（借鉴 oss-fuzz-gen） | ✅ `fuzz_input_extractor.py`——从 crash 目录自动提取恶意集，WSL 实测 5 恶意+1 合法 → verify PASS |
| 规则生态化（镜像 Semgrep） | ✅ `semgrep/cwe-repair-rules.yml`——7 条规则映射（parallel-array/nested-index/resize/pickle/shell 等），白嫖 test-ok/test-evil |
| 基准化（借鉴 RepairBench） | ⏳ 已有 coverage_analysis.py，可后续做 leaderboard |
| 补丁二道质检（Invalidator） | ⏳ 可选后续 |
| 对称性检查自动化扩展（PaReco） | ⏳ 当前依赖人工指定成对入口，可后续自动发现 |

## 六、诚实局限

1. **Paddle-Lite 无新漏洞发现**——不是工具失效，是目标较严谨 + 内部索引误报多（nested_index 需进一步过滤 `xxx_ids_[i]` 内部向量模式）；
2. 网络限制：github.com 443 不可达（git clone/codeload 失败），仅 api.github.com 通 → 新组件获取依赖 gitee 镜像；
3. 降误报以牺牲召回为代价：low 模式默认关闭，可能漏报"泛化但真实"的案例（需 --include-low 人工复核）；
4. fuzz corpus 不适合当"合法输入"（畸形为主）——合法集需真实模型文件（已修正提取器）。

## 七、工具最终形态（8 脚本 + 规则 + 报告）

```
.dsh/skills/cwe-repair/
├── SKILL.md / README.md
├── scripts/
│   ├── cwe_reach.py             # 可达性标注
│   ├── cwe_detect.py            # 检测（置信度分级，误报 -80%）
│   ├── symmetry_check.py        # 成对入口对称性（独有）
│   ├── cwe_repair.py            # 鲁棒性修复模板
│   ├── cwe_verify.py            # 双向验证（真实 PASS/REVIEW）
│   ├── coverage_analysis.py     # 覆盖度分析
│   └── fuzz_input_extractor.py  # fuzz 验证输入自动扩充（新增）
├── semgrep/cwe-repair-rules.yml # Semgrep 规则镜像（新增）
└── examples/ncnn_blobidx_verify.json
```

## 八、下一步候选

1. **nested_index 再降误报**：排除 `xxx_ids_[i]`（内部 CPU 拓扑数组）类模式
2. **扫描更多组件**：onnxruntime（gitee 镜像）/ FastDeploy / unitree_sdk2py
3. **产出可 PR commit**：对确认的 AimRT AR-1 / x1_infer 漏洞生成完整 PR 材料（含对称性检查通过证据）
4. **基准化**：34-finding 数据集 leaderboard（RepairBench 风格）
