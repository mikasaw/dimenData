# dimenData — Windows 硬件信息采集与设备指纹工具

[![CI](https://github.com/mikasaw/dimenData/actions/workflows/ci.yml/badge.svg)](https://github.com/mikasaw/dimenData/actions/workflows/ci.yml)

**语言：** 中文 | [English](README_EN.md)

采集 Windows 设备关键硬件与系统标识信息，生成设备指纹（软件授权/设备绑定主场景，兼 IT 资产管理）。

> ⚠️ **隐私提示**：本工具读取设备标识（主板/整机/磁盘序列号、SMBIOS UUID、网卡 MAC、GPU UUID、
> OS 标识等），产出的报告含设备可识别信息——请按敏感数据处理，勿提交到公开仓库。
> 本仓库文档与测试夹具中的所有设备标识均已打码或替换为合成示例。

## 设计要点

- **模块化多通道采集**：每种采集手段（smbios / wmi / registry / native / cpuid…）实现统一
  `IChannel` 接口并自注册进 `ChannelRegistry`，同时启用、线程池并发执行；同一字段多通道
  结果按 `FIRST_BY_PRIORITY` / `CONSENSUS`（交叉验证）/ `MERGE_LIST`（多重重集合并）/
  `CONSENSUS_ALIGNED`（逐实例对齐，如磁盘按盘位）策略归并。
- **指纹算法**：字段规范化（cpu.id 字节序统一 R1/R2、磁盘序列号 R4、日期 R12）→
  加权选取 → SHA-256（CNG）；整机指纹 + 部件子指纹（bios/board/cpu/disk/gpu/memory/nic/os/sys）
  + 组权重相似度评分（容忍小硬件变更）。
- **算法版本戳**：指纹由「字段集 + 权重 + 规范化规则」共同决定，报告写入 `fingerprint.algo`；
  版本变更后 `--verify` 会明确报告"算法已演进"（`algorithm_changed:true`、`integrity:null`、
  退出码 4），而不会误报为报告被篡改。
- **零第三方运行时依赖**：哈希用 Windows CNG，静态链接 CRT，`build/hwfp.exe` 单文件可分发。
  仓库内的 JSON 解析/序列化、单测框架、线程池均为自研——**未引入任何外部库代码**（无 vendored 源码、
  无第三方链接）；`开发计划.md` §3.1 中列出的 nlohmann/json、GoogleTest、CMake 等仅为当初评估过的备选，
  实际未采用。
- **离线授权闭环**（`src/license/`）：RSA-2048 + SHA-256 + PKCS#1 v1.5 签名（纯 CNG，
  Ed25519 不在 CNG 提供范围）；`keygen` 生成密钥对 → `license --issue` 对 canonical
  授权文本签名（可绑定整机指纹或签发浮动授权）→ `license --check` 验签 + 有效期 +
  机器绑定校验（组权重相似度阈值，默认 0.85，容忍小硬件变更）。授权载荷的 sub/features
  均参与签名，篡改任一字段即验签失败。

## 构建（MSVC，无 CMake）

```bat
build.cmd               # 构建并运行全部单测（69 用例）
build.cmd app           # 构建 build\hwfp.exe
build.cmd smoke         # 构建并运行冒烟（归并采集 + 指纹）
build.cmd fuzz 200000   # 构建并运行确定性模糊测试（缺省 20 万轮）
build.cmd dll           # 构建 build\hwfp.dll（C ABI 集成库）
build.cmd dlltest       # 构建 hwfp.dll 并运行集成消费者自检
build.cmd clean         # 清理 build 目录与散落的 .obj
```

需要 VS（当前 VS 18 Insiders 工具集，vcvars64.bat 路径见 build.cmd）。

## hwfp.dll 集成接口（C ABI）

`build/hwfp.dll` 供宿主应用直接加载（隐式链接 build/hwfp.lib 或 LoadLibrary），
字符串一律 UTF-8，输出缓冲用 `Hwfp_Free` 释放（静态 CRT，不可跨模块 free）：

```c
#include "dll/hwfp_dll.h"          // 随仓库分发，纯头文件无依赖

Hwfp_Version();                    // "0.1.0"
Hwfp_Collect(&json);               // 采集+指纹 → schema v1 JSON（默认配置）
Hwfp_CollectWithConfig(cfg, &j);   // 同上，配置 JSON 文本由调用方给定
Hwfp_CheckLicense(lic, pub, 0.85, &result);
                                   // 返回 0 有效 / 5 格式或签名无效 /
                                   // 6 过期或机器不匹配 / 3 采集失败 / 2 参数错误
Hwfp_Free(p);
```

DLL 不隐式读取配置文件（默认配置 = 全通道默认优先级/权重）；各入口独立可重入。
`build.cmd dlltest` 会构建 hwfp.dll 并运行 `tools/dll_consumer.cpp` 集成自检。

## hwfp.exe 使用

```bat
hwfp.exe                                  :: 采集，schema v1 JSON 输出到 stdout
hwfp.exe --config config/hwfp.json -o report.json
hwfp.exe --text                           :: 人类可读摘要
hwfp.exe --verify report.json             :: 与历史报告比对（完整性 + 相似度）
hwfp.exe --fields                         :: 列出字段键/归并策略/权重
hwfp.exe keygen --privkey k.priv --pubkey k.pub   :: 生成授权密钥对（RSA-2048）
hwfp.exe license --issue --licensee 客户A --privkey k.priv [--expires 2027-12-31]
                                          :: 签发授权（默认绑定本机指纹；--floating 浮动）
hwfp.exe license --check license.json --pubkey k.pub [--threshold 0.85]
                                          :: 校验授权（签名 + 有效期 + 机器绑定）
:: 退出码：0 通过/有效 / 2 参数或配置错误 / 3 采集·完整性·密钥操作失败
::         4 算法版本不一致 / 5 授权格式或签名无效 / 6 授权过期或机器不匹配
```

配置（`config/hwfp.json`）：通道启停与优先级、字段归并策略与权重（支持 `memory.*` 通配）、
并发数、wmi 的 `tpm_probe`（默认关闭：部分主板连接 MicrosoftTpm 命名空间固定阻塞 ~5s，
见矩阵 R16）。

## 测试与模糊测试

- **单测**：69 用例，零依赖自研框架（`tests/`），解析器与授权夹具全部为合成值。
- **模糊测试**（`tools/fuzz_main.cpp`，`build.cmd fuzz [轮数] [种子]`）：七个目标
  （json / config / smbios / edid / nvidiasmi / pipeline / license），确定性种子、内建
  判定 oracle——合法基线精确还原、失败必有错误信息、JSON 数值文本自稳定、nvidia-smi
  CSV 与独立重实现逐字段对账、归并结构不变量、报告往返指纹一致、被接受授权的语义
  字段必须与原件一致；失败打印复现种子并落盘 `build/fuzz_repro_<目标>.bin`
  （曾捕获 `NumberToString` 的 `%.6g` 指数形态文本漂移）。
- **CI**（GitHub Actions `windows-latest`）：单测 → 构建 hwfp.exe → CLI 自检 → 冒烟采集
  （真实标识只留在临时 runner、不进公开日志）→ fuzz；每周一次 200 万轮长跑。

## 文档

- [开发计划](开发计划.md)（模块化多通道架构 / 里程碑 / 风险）
- [M1 POC 采集项可用性矩阵](docs/M1-POC-采集项可用性矩阵.md)（双环境实测 + 17 条规范化规则 R1-R17）
- [数据结构](docs/数据结构.md)（采集报告 schema v1 / verify·license 输出 / 授权文件与 canonical）
- [English README](README_EN.md)（英文入口；两份深度文档目前为中文）

发布自动化：`.github/workflows/release.yml` 在推送 `v*` 标签（或手动触发）时在
GitHub runner 构建未签名的 hwfp.exe/hwfp.dll 并发布为 GitHub Release（代码签名
需证书，见"当前进度"待办）。

## 当前进度

| 里程碑 | 状态 |
|---|---|
| M1 技术验证 POC | ✅ 宿主机 + VMware 双环境验证 |
| M2 采集框架（模块化多通道） | ✅ 4 通道 + 调度器 + 归并器（验收通过） |
| M3 指纹引擎 | ✅ 规范化/加权/整机+子指纹/相似度（验收通过） |
| M4 CLI 与输出 | ✅ hwfp.exe（schema v1 / verify / 配置化） |
| 集成验证 | ✅ 宿主机 86 实例 ~210ms；VM 44 实例 ~460ms；同机指纹逐字节一致 |
| 待办 | TPM 管理员权限复测、≥3 台品牌物理机补测、代码签名（发布包自动化已上线，当前产物未签名） |

## 目录结构

```
src/core/        字段表（fields.def）、IChannel/ChannelRegistry、归并器、调度器、JSON、配置
src/channels/    通道模块：smbios / registry / native / wmi（+ 纯函数解析器）
src/fingerprint/ 指纹引擎（规范化/加权/SHA-256）与 CNG 封装
src/license/     离线授权（RSA-2048 签名 / canonical / 校验）
src/dll/         hwfp.dll C ABI 导出（含公共头 hwfp_dll.h）
src/cli/         hwfp.exe 入口与报告（schema v1）构建/解析
tests/           零依赖单测（69 用例）
tools/           冒烟入口、确定性模糊测试入口、DLL 集成消费者
poc/             M1 验证用采集 demo（作为工程留痕保留）
config/          默认配置
docs/            M1 采集项可用性矩阵（实测值 + R1–R17 规则）
```

## 已知限制

- WMI 半同步枚举不可安全中断，单查询无硬超时（记录在配置 per_task_timeout_ms）；
- 虚拟设备按 PNP 总线前缀过滤（R6）：ROOT/SWD 类软件显示设备（GameViewer 虚拟显示、
  Microsoft 基本显示）与虚拟网卡（VMware VMnet）已剔除；VM 内 PCI 总线的虚拟显示
  适配器（VMware SVGA/VirtualBox/QXL/Virtio）按"该机真实显示硬件"保留；
- 内存序列号不可靠（R8），仅容量/条数参与指纹；磁盘按盘位对齐（ConsensusAligned，R5）；
  网卡按 MAC 实例对齐（T12：wmi 冒号形态与 native 连续 hex 在组键上归一后配对，
  每块物理网卡一条名称——native 优先，跨通道一致时 confidence=high）；
  内存暂不做实例对齐：跨通道槽位键口径（DeviceLocator/BankLocator 的取舍）与
  PartNumber 等值的编码差异未做实测收敛，强行对齐会改变值多重集导致指纹漂移
  （列为后续任务，落地时需 A/B 实测并评估 kAlgoVersion 升版）；
- TPM 字段默认不探测（R16：部分主板连接该命名空间阻塞 ~5s，`tpm_probe: 1` 开启）；
- `gpu.uuid` 采集需 spawn `nvidia-smi`（System32 绝对路径、3s 硬超时、句柄白名单继承），
  属杀软/EDR 关注的进程创建行为；消费级显卡无序列号，UUID 为其唯一稳定标识（R17）。
  **该字段参与指纹**（gpu 组权重 5）：仅 NVIDIA 平台有值（AMD/Intel 不产生该组，指纹不受影响），
  换/加显卡会改变整机指纹与 gpu 子指纹（授权强绑定场景需知悉）。
- `--verify` 的重算使用**当前配置的权重**，须与生成报告时一致；输出中的 `weights_override`
  提示本次是否使用了配置覆盖（使用了则 integrity 判定仅在两者一致时有意义）。

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功（`--verify` 完整性通过；`license --check` 授权有效） |
| 2 | 参数或配置错误 |
| 3 | 采集失败，或 `--verify` 判定报告被篡改，或密钥操作失败 |
| 4 | `--verify` 时报告算法版本与当前不一致（完整性不可判定，`match`/`similarity` 仍有效） |
| 5 | `license --check` 授权文件格式或签名无效 |
| 6 | `license --check` 授权已过期或机器不匹配 |

（hwfp.dll 各导出的返回码沿用同一语义。）

## 许可

[MIT License](LICENSE) © 2026 mikasaw
