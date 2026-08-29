# 具身AI模型漏洞挖掘——路线图 v2（修正版）

> **修正原因**：OpenVLA 需要 16GB 显存跑不动，但这不是问题——
> ONNX Runtime fuzz 不需要 GPU，产出 CVE 概率更高，且同样属于"AI安全"

---

## 新结构：一条主线 + 一条辅线

```
主线（80%时间，出CVE）          辅线（20%时间，理解攻击概念）
━━━━━━━━━━━━━━━━━━━━━━━━━━    ━━━━━━━━━━━━━━━━━━━━━━━━━━
对 ONNX Runtime 做传统 fuzz     理解对抗攻击的基本原理
目标：发现反序列化 CVE           目标：跑通 FGSM，读 CHAI 摘要
                                            ↓
               两条线在"写论文"时汇合：
  "我们发现 ONNX Runtime 的模型加载漏洞
   → 攻击者可利用此漏洞注入恶意模型
   → 影响所有使用 ONNX 部署的具身AI系统
   包括：OpenVLA、YOLOv8、CLIP、..."
```

---

## 一、主线：ONNX Runtime fuzz（本周立即开始）

### 1.1 为什么 ONNX Runtime 是最佳目标

| 理由 | 说明 |
|------|------|
| **和AI安全直接相关** | 它是AI模型的"操作系统"，所有模型部署都经过它 |
| **C++实现，适合fuzz** | 模型反序列化代码是C/C++，存在内存安全漏洞 |
| **已有历史CVE** | 说明确实有漏洞，审计不充分 |
| **不用GPU** | CPU上编译+fuzz即可 |
| **产CVE概率高** | 解析复杂格式（Protobuf）的代码最容易出bug |
| **导师认可** | "AI供应链安全"是顶会热门方向 |

### 1.2 本周（7月27日-8月2日）ONNX Runtime fuzz 计划

#### 第1-2天：编译 ONNX Runtime + 理解模型加载流程

```bash
# 进入 WSL2
wsl

# 安装依赖
sudo apt install -y cmake build-essential python3-dev protobuf-compiler

# 克隆（精简版，只拿必要代码）
cd ~/fuzz-lab
git clone --depth 1 https://github.com/microsoft/onnxruntime.git
cd onnxruntime

# 先看关键文件：模型是怎么加载的
# ONNX 文件格式 = Protobuf
# 加载入口在 onnxruntime/core/graph/
ls onnxruntime/core/graph/model.cc
ls onnxruntime/core/graph/graph.cc

# 搜索所有反序列化相关函数（这是你的fuzz目标列表）
grep -rn "LoadModel\|MergeFromString\|ParseFromString\|Deserialize" \
  onnxruntime/core/graph/ | head -20
```

**产出**：确认一个具体的 fuzz 入口函数

#### 第3-4天：写第一个 ONNX Runtime harness

```bash
# 目标：写一个 libfuzzer harness，对 ONNX 模型文件的 Protobuf 反序列化做 fuzz

cat > fuzz_onnx_model.cc << 'EOF'
#include <cstdint>
#include <cstddef>
#include <string>

// ONNX Runtime 模型加载的核心是 Protobuf 解析
// 你的 harness 直接 fuzz 它：
#include "onnx/onnx-ml.pb.h"  // ONNX 的 Protobuf 定义

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);
    
    onnx::ModelProto model;
    // 这里就是反序列化入口——所有 ONNX 模型加载的必经之路
    model.ParseFromString(input);
    
    return 0;
}
EOF
```

**产出**：一个能编译的 harness 框架

#### 第5-7天：编译 + 开始跑 fuzz

```bash
# 用 clang + ASAN + libfuzzer 编译 ONNX Runtime（精简版）
# 具体命令在第3-4天根据 ONNX Runtime 的 cmake 配置确定

# 目标：让 fuzz 跑起来
# 跑通后让它持续运行，每天检查 crash
```

**产出**：ONNX Runtime fuzz 在后台运行，有一个种子语料库

### 1.3 第2周以后：跑 fuzz + 分析 crash

```
第2周：让 fuzz 24小时跑，同时研究 crash 分析方法
第3周：分析 crash，判断是否有安全价值
第4周：如果有发现 → 提交 CVE；如果没有 → 换第二个目标
```

---

## 二、辅线：对抗攻击理解（本周只需 2 小时）

### 2.1 目标：跑通 FGSM，理解就够了

```bash
# 在 WSL2 中执行（全 CPU，不需要 GPU）
cd ~/fuzz-lab
mkdir 02-adversarial && cd 02-adversarial

pip3 install torch torchvision matplotlib pillow

# 创建并运行 FGSM 脚本
cat > fgsm_mini.py << 'PYEOF'
"""
最小 FGSM 演示：只用 20 行核心代码
"""
import torch, torchvision.models as models
from PIL import Image
import torchvision.transforms as T

# 加载模型
model = models.resnet18(pretrained=True).eval()

# 图片 → tensor
img = Image.new('RGB', (224,224), color=(128,128,200))
x = T.Compose([T.ToTensor(), T.Normalize([0.485,0.456,0.406],[0.229,0.224,0.225])])(img).unsqueeze(0)
x.requires_grad = True

# 原始预测
pred_before = model(x).argmax().item()
print(f"原图预测: 类别 #{pred_before}")

# FGSM 攻击
loss = torch.nn.CrossEntropyLoss()(model(x), torch.tensor([pred_before]))
loss.backward()
x_adv = (x + 0.03 * x.grad.sign()).detach()

# 对抗样本预测
pred_after = model(x_adv).argmax().item()
print(f"对抗样本预测: 类别 #{pred_after}")
print(f"{'🎉 攻击成功!' if pred_after != pred_before else '❌ 失败'}")
PYEOF

python3 fgsm_mini.py
```

**这就是全部。** 你只需理解：加人类不可见的噪声 → 模型分类错误。

### 2.2 辅线为什么只做这么多

```
你需要对抗攻击知识的目的：
  ✅ 在论文里写 "我们发现 ONNX Runtime 漏洞可被利用来注入恶意模型"
  ✅ 在综述里讨论 "对抗攻击是具身AI的另一类威胁"
  ✅ 和导师交流时能说 "我了解攻击面全貌"
  
你不需要的：
  ❌ 现在就去跑 OpenVLA 完整推理（需要GPU，浪费时间）
  ❌ 复现 CHAI 全部实验（等有 GPU 再说）
  ❌ 做出 SOTA 的对抗攻击（那不是你的赛道）
```

---

## 三、修正后每周计划

```
第一周（7/27-8/02）
  🔥 主线：编译 ONNX Runtime → 理解加载流程 → 写第一个 harness
  📖 辅线：跑通 FGSM 最小示例（2小时）

第二周（8/03-8/09）
  🔥 主线：ONNX Runtime fuzz 跑起来 → 收集 crash
  📖 辅线：读 ONNX Runtime 历史 CVE，理解"什么算漏洞"

第三周（8/10-8/16）
  🔥 主线：分析 crash → 判断安全价值 → 准备 CVE 报告
  📖 辅线：读 CHAI 论文摘要（纯阅读，不跑代码）

第四周（8/17-8/23）
  🔥 主线：提交 CVE / 换第二个目标继续 fuzz
  📖 辅线：开始写第一份学期技术报告
```

---

## 四、论文方向（更新后）

| 方向 | 难度 | GPU需求 | CVE概率 | 你的选择 |
|------|------|---------|---------|---------|
| ONNX Runtime反序列化漏洞 | 🟡 | 无 | ⭐⭐⭐⭐⭐ | **🔥 主力** |
| ONNX Runtime的CVE系统性分析 | 🟢 | 无 | — | 备选（综述型） |
| VLA模型对抗攻击 | 🔴 | 16GB+ | 不适用 | 大四再做 |
| 视觉提示注入 | 🟡 | 8GB+ | 不适用 | 有GPU后做 |

**你的大三上论文最可能长这样**：

> 《面向具身AI推理引擎的安全分析：以ONNX Runtime为例》
>
> 内容：
> - 我们对 ONNX Runtime 进行了模糊测试
> - 发现了 N 个漏洞（CVE-2026-xxxx, CVE-2026-yyyy）
> - 分析了这些漏洞在具身AI场景下的危害
>   - 攻击者通过 HuggingFace 发布"恶意模型"
>   - 机器人下载并加载 → 触发 ONNX Runtime 漏洞
>   - 攻击者在机器人系统上获得代码执行权限
> - 提出了防御建议

---

## 五、明天（7月27日）5件事

```
□ 1. 克隆 ONNX Runtime: git clone --depth 1 https://github.com/microsoft/onnxruntime.git
□ 2. 找到模型加载入口函数（grep搜索 LoadModel/ParseFromString）
□ 3. 阅读 ONNX Runtime 已有 CVE（NVD搜索 "ONNX Runtime"）
□ 4. 跑通 FGSM 最小示例（20行版本，2小时）
□ 5. 写 7/27 学习笔记
```

---

## 六、关键认知修正

| 之前的错误想法 | 正确理解 |
|---------------|---------|
| "需要搭 OpenVLA 才能开始" | ❌ ONNX Runtime fuzz 完全独立，不需要 OpenVLA |
| "对抗攻击需要 GPU" | ❌ FGSM 在 CPU 上秒出结果 |
| "fuzz 和 AI 安全是两回事" | ❌ ONNX Runtime 就是 AI 基础设施的"操作系统" |
| "没 GPU 做不了 AI 安全" | ❌ AI 安全的"底层"（软件供应链）不需要 GPU |

---

> **一句话总结**：你的赛道是 **AI 模型的软件供应链安全**——不是设计新的攻击算法，而是在 AI 模型部署的底层引擎里挖传统漏洞。这在学术上叫 "AI Infrastructure Security"，是 2025-2026 年顶会的新兴方向。你的 fuzz 技能 + 导师的 AI 安全方向，恰好在这个交叉点上。
