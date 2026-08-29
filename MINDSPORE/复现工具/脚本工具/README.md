# MindSpore load_checkpoint 漏洞测试脚本（2026-08-07）

Task 2（dims 截断/负值变体矩阵）与 Task 1（RCE 尝试）的实证脚本。

## 环境

- WSL2 Ubuntu-22.04，用户 kaltsit，mindspore 2.8.0（venv：`/home/kaltsit/ms_env/bin/python`）
- 脚本内硬编码了 WSL 解释器路径；运行时需先 cp 到 WSL（如 `/tmp/`），或用已建好的 `~/vuln_repro/mindspore/` 目录
- Git Bash 调用 WSL 需 `MSYS_NO_PATHCONV=1` 前缀避免 `/home/...` 被转成 Windows 路径

## 脚本用途

| 脚本 | 用途 |
|------|------|
| `run_case.py` | 单 case 测试：`python run_case.py "<dims_csv>" <content_bytes> <dtype>` → VERDICT（CRASH/EXC/OK） |
| `matrix_scan.py` | 矩阵扫描：`python matrix_scan.py <dtype>` → 98 行 TSV（14 dims × 7 长度），8 线程并发 |
| `aggregate.py` | 汇总 `/tmp/ms_*.tsv` 全部 dtype 矩阵，输出 dims×长度 网格 + 跨 dtype 分歧 |
| `mval.py` | 多 value 堆布局实验：溢出源/正常 Tensor 不同顺序 → 崩溃模式差异 |
| `run_mval.py` | gdb 入口：`gdb -batch -ex run --args python run_mval.py <ckpt>` |
| `morph_test.py` | 畸形对象二次触发：dims=[-5] 静默返回的 Parameter 被用户访问的影响 |
| `probe_tensor.py` | 探针：直接调 `Tensor.convert_bytes_to_tensor` 看负 dims 的 Tensor 构造行为 |
| `sc_dbg.py` | 单 case 完整 stderr：-5 vs -1 差异根因（parameter.py 只查 -1） |
| `mallocshim.c` | LD_PRELOAD malloc shim：重建堆分配序列（`gcc -shared -fPIC -o /tmp/mallocshim.so mallocshim.c -ldl`） |
| `exp_neg5.py` / `runner_neg5.py` | -5 畸形 Parameter 网络路径场景矩阵：`python runner_neg5.py` 构造恶意 ckpt 并逐场景隔离跑（into_net/skip_infer/skip_train/save/delayed/load_only，cb=4B/28B） |
| `cycle_test.py` | save_checkpoint 传播闭环验证：加载畸形→保存→再加载循环 3 轮（结论：静默空文件，非二次投毒） |
| `mix_save.py` | 混合 dict（正常+畸形）保存：验证畸形参数被静默丢弃、正常参数保留 |

## 关键结论速查

- `cast<int>` int64→int32：超界抛 RuntimeError 无回绕；int32 范围负 dims 通过 → 0 字节缓冲 → 越界写
- 崩溃阈值 = 写字节 > glibc chunk usable size（0 字节缓冲最小 chunk 24B；≥32B 覆盖 header 崩）
- `parameter.py:308` 只查 `-1 in shape`，其他负 dims 绕过 → dims=[-5] 静默返回畸形 Parameter
- 多 value `[b正常,a溢出]` → SIGSEGV@_int_malloc（fastbin fd 被 0x41 污染）→ RCE 原语家族，但完整链 UNLIKELY（glibc 2.35 safe-linking）
- 网络路径（exp_neg5/runner_neg5）：tag 不匹配 → load_param_into_net 静默跳过，推理/训练全正常；**cb=28B 越界 → 业务全正常但退出 rc=-6 延迟崩溃（投毒在加载瞬间）**；save 对畸形参数 = 静默丢数据（非二次投毒）

详细分析见 `../漏洞分析-MindSpore-堆溢出-2026-08-07.md` section 十一/十二。
