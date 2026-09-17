# M1 POC — 采集项可用性矩阵（实测）

> 日期：2026-09-16　POC 产物：`poc/poc_hwfp.exe`（MSVC 14.51 `/MT` 单文件，零第三方依赖）
> 原始输出：`poc/out_host.txt`（宿主机）、`poc/out_vm.txt`（虚拟机，含 guest 侧 SHA256 校验记录）
> 脱敏说明：本文档所有设备标识（序列号/UUID/MAC/GUID/产品 ID/PCI 路径）均已打码或替换为合成示例，真实值不公开；保留机型与厂商名（公开信息）以说明结论。

---

## 1. 验证环境

| # | 环境 | 系统 | 关键硬件 | 采集耗时 |
|---|---|---|---|---|
| H1 | 宿主物理机 | Windows 11 25H2 (26200) x64 | AM5 平台（Ryzen 9000 系列）/ 2×16G DDR5 / 3 块磁盘 / 双 NVIDIA 独显 + 核显 | 5187 ms |
| V1 | VMware Workstation（test2） | Windows 10 x64 | 440BX 虚拟平台 / 2 vCPU / 4G / VMware NVMe 虚拟盘 | 172 ms |

## 2. 通道可用性结论

| 通道 | H1 | V1 | 结论 |
|---|---|---|---|
| smbios（GetSystemFirmwareTable 直读） | ✅ SMBIOS 3.7 | ✅ SMBIOS 2.7 | 两环境全通，**主板/BIOS/整机的首选主通道**（不依赖 WMI 服务） |
| wmi（ROOT\CIMV2） | ✅ 88/90 字段 | ✅ 48/56 | 字段最全；但 `PhysicalAdapter=TRUE` 过滤不可靠（见 R6） |
| registry | ✅ 26/27 | ⚠️ 4/6（无 EDID） | MachineGuid/版本信息全通；EDID 依赖真实显示器，VM 下自然缺失（降级路径符合预期） |
| native（CPUID/GAA/CNG/IOCTL/TBS） | ✅ | ✅ | CPUID、物理网卡 MAC、CNG SHA-256、StorageDeviceProperty 全通过；TBS 两环境都报未找到 TPM（见 R14） |

字段统计：H1 共 175 项、取到 157 项；V1 共 874 项、取到 345 项。V1 项数膨胀是因为 POC 未去重（VM 输出 16 份 CPU 结构、16 个内存槽位，见 R10），正式版 `fields.def` + 过滤规则解决。

## 3. 逐字段矩阵（H1 实测值，V1 对照）

| 字段 | 推荐通道 | 备用通道 | H1 实测值（脱敏） | V1 实测值 | 备注 |
|---|---|---|---|---|---|
| bios.vendor | smbios | wmi | American Megatrends International, LLC. | Phoenix Technologies LTD | 一致 |
| bios.version | smbios | wmi | A.H0 | 6.00 | 一致 |
| bios.release_date | smbios | wmi | 07/25/2024 | 11/12/2020 | WMI 返回 CIM 格式（R12） |
| sys.manufacturer / product | smbios | wmi | Micro-Star / MS-\*\*\*\* | VMware, Inc. / VMware Virtual Platform | 一致 |
| sys.serial | smbios | wmi | To be filled by O.E.M.（占位，R3） | VMware-\*\* \*\* \*\* \*\* … | 组装机常见占位 |
| sys.uuid | smbios | — | A1B2C3D4\*\*\*\*…\*\*\*\*FFFF | 564D\*\*\*\*…\*\*\*\*\*\*\*\* | 尾 6 字节=主网卡 MAC（R15） |
| board.serial | smbios | wmi | 07D7\*\*\*\*\*\*\*\*4822 | None（占位，R3） | **双通道一致，CONSENSUS 示范字段** |
| cpu.id / processor_id | smbios | wmi | 4433221188776655 ↔ 5566778811223344 | 每 vCPU 不同（R2） | 同信息异字节序（R1） |
| cpu.name / brand | native | smbios/wmi | Ryzen 7 9000 系列 8-Core Processor | 同左（透传宿主） | 一致 |
| memory[*].serial/manufacturer | wmi | smbios | serial=00000190（占位级）、manufacturer 空 | 全空 | **内存序列号不可靠（R8）** |
| memory[*].size | wmi | smbios | 2×17179869184 字节 | 1×4G + 15 空槽 | 空槽需过滤（R10） |
| disk.model/serial | native | wmi | GW26\*\*\*\*\*\*\*\*0583（系统盘） | VMWare NVME_0000 | **双通道一致（R5）**；WMI NVMe 序列号带 `_` 和尾点（R4） |
| nic.mac（物理） | native | wmi | 34:5A:60:\*\*:\*\*:\*\*（有线）、3C:0A:F3:\*\*:\*\*:\*\*（Wi-Fi） | 00:0C:29:\*\*:\*\*:\*\*（KD 网卡） | WMI PhysicalAdapter 混入 VMware 网卡（R6） |
| gpu.name | wmi | — | 独显×2 / 核显 / 虚拟显示 | VMware SVGA | 虚拟显卡需过滤（R6） |
| gpu.uuid | native（nvidia-smi） | — | GPU-01234567…（示例）/ GPU-fedcba98…（示例） | 无（非 NVIDIA，降级） | NVIDIA 卡级唯一标识；**参与指纹**（gpu 组权重 5，算法 v2）；消费级卡无序列号（见 R17） |
| monitor[*]（EDID） | registry | — | AUS/DEL/SAC×2/SKG×3（含幽灵重复，R9） | 无 | **不入指纹（权重 0）** |
| os.machine_guid | registry | — | cdc6\*\*\*\*-\*\*\*\*-\*\*\*\*-\*\*\*\*-\*\*\*\*f8e6bc22 | \*\*\*\*\*\*\*\*-… | 重装系统会变，低权重 |
| os.product_id / install_date | registry | — | 00328-\*\*\*\*\*-\*\*\*\*\*-AA454 / 2026-08 | 00330-\*\*\*\*\*\*-… / 2026-08 | 同上 |
| os.secure_boot | registry | — | 键不存在 | 键不存在 | 只采集不入指纹 |
| tpm | native+wmi | — | TBS 0x8028400F（未找到/未启用） | 同左 | 待管理员权限复测（R14） |
| crypto.sha256（CNG） | native | — | pass（"abc" 参考值比对） | pass | 指纹哈希基础能力就绪 |

## 4. 关键发现 → 规范化规则（落入 M2/M3）

| # | 发现 | 落地规则 |
|---|---|---|
| R1 | SMBIOS `cpu.id`（4433221188776655）与 WMI `ProcessorId`（5566778811223344）是**同一信息的两种字节序**（EAX/EDX 各按小端 vs EDX:EAX 大端） | M3 归一化：统一解析为 (EAX,EDX) 二元组后哈希；CONSENSUS 比较前先归一 |
| R2 | VM 多 socket 下每个 vCPU 的 ProcessorId 不同（低字节为 APIC ID） | cpu.id 归一化时屏蔽低字节；CPU 子指纹只取特征+型号+核心数 |
| R3 | 占位符值："To be filled by O.E.M."、"None"、"Unknown"、SMBIOS 串 idx=0 | 建立**占位符黑名单**（含大小写/空格变体），命中的字段视为无效，不参与哈希，清单中标记 `placeholder=true` |
| R4 | WMI NVMe 磁盘序列号含下划线与尾点（`6479_****_****_00B0.`） | 磁盘序列号归一化：strip `[ _.- ]` 后再入哈希。**对照结论（2026-09-17）**：宿主机三块盘（SATA×2+NVMe）StorageDeviceProperty 与 WMI 逐字符一致，现代存储栈未见字节序差异；回归测试 `disk_serial_sata_r4_cross_channel` 已锁定 |
| R5 | StorageDeviceProperty 与 WMI 磁盘序列号**双环境一致**；但 WMI 返回顺序非升序（真机实测 Index 顺序 1,0,2），通用合并去重会错位 | **逐盘实例对齐已实现（2026-09-17）**：`instance_key`=盘位号（native 用 PhysicalDriveN、WMI 用 Index），新增 `ConsensusAligned` 策略——同一盘位跨通道配对验证（一致→high，分歧→fallback 取最高优先级，单通道→single），输出按盘位数值序排列；磁盘四字段（model/serial/firmware/size_bytes）全部对齐 |
| R6 | WMI `PhysicalAdapter=TRUE` 混入 VMware VMnet；显卡混入虚拟显示适配器（真机实测 GameViewer 虚拟显示适配器 PNP=`ROOT\DISPLAY`，真显卡均 `PCI\VEN_*`） | **已完成（2026-09-17）**：NIC 按 PNP 总线白名单过滤（仅 PCI/USB；ROOT/SWD/ACPI/VMBUS 排除——Hyper-V/Xen guest 合成网卡走 VMBUS 前缀会被排除，属"虚拟硬件不算物理"的正确行为）；GPU 按 PCI 白名单 + 名称黑名单（virtual display / virtual adapter / indirect display / gameviewer / usbmmidd / iddsampledriver / remote display / basic display / parsec / spacedesk / mirror driver / displaylink）。真机验证：VMnet 2 条 MAC 全部剔除、GameViewer 虚拟显示适配器剔除（gpu 列表仅剩 RTX3060/RTX5060Ti/核显） |
| R7 | GetAdaptersAddresses 只返回**已连接**网卡（V1 主网卡禁用时缺失） | M2 用 CfgMgr32/SetupAPI 补枚举 PCI 网卡（含禁用态），GAA 作为运行态补充 |
| R8 | 内存 SPD 序列号/厂商大面积缺失或占位 | 内存序列号**不入指纹**（仅清单）；内存子指纹只用容量条数组合 |
| R9 | 注册表 EDID 存在幽灵/重复显示器实例（serial=0/1） | 显示器维持不入指纹；如做资产清单需与 `EnumDisplayDevices` 当前拓扑交叉过滤 |
| R10 | VM 输出 16 份 Type4/Type17 结构、大量空槽 | 按 handle+类型去重；Type17 过滤 `size==0`；Type4 每 socket 取一份 |
| R11 | WMI 网卡速度字段溢出（9223372036854775807） | 速度类字段弃用 WMI，走 native |
| R12 | WMI CIM 日期 `20240725000000.000000+000` | 日期归一化为 `YYYY-MM-DD` |
| R13 | H1 全程串行 5187ms（超 2s 目标）；V1 仅 172ms | M2 线程池并发（规划已有）+ SMBIOS 优先于 WMI；H1 慢源是 WMI 串行查询与安全软件钩子 |
| R14 | 两环境 TBS 均 0x8028400F、MicrosoftTpm 命名空间不可达 | 管理员权限复测后再决定字段去留；无 TPM 环境自然降级 |
| R15 | MSI 板 SMBIOS UUID 尾部 6 字节 = 主网卡 MAC | UUID 可作整机指纹高权重候选；VM 下 UUID 与 BIOS 序列号同源，防虚拟机克隆需服务端另判 |
| R17 | **消费级显卡无序列号**：WMI `Win32_VideoController` 无该属性、PnP 属性无（ContainerId 未填充）、注册表仅机器派生的 VideoID/AOCID、`nvidia-smi` 的 serial 列返回 `[N/A]`/`0`（厂商未烧录，仅数据中心卡有真值） | 改用 **GPU UUID**（nvidia-smi，卡级唯一稳定）：`gpu.uuid` **参与指纹**（独立 `gpu` 子指纹组，权重 5/165；换卡相似度约扣 3%）。覆盖局限：仅 NVIDIA 有值，AMD/Intel 平台不产生该组、指纹照常。采集需 spawn 第三方进程（System32 权威路径 + 3s 硬超时 + 句柄白名单，属杀软关注行为）；提权导致指纹变化，由**指纹算法版本戳**（kAlgoVersion，报告 `fingerprint.algo`）区分"算法演进 vs 报告被篡改" |
| R16 | **MicrosoftTpm 命名空间 ConnectServer 在部分主板固定阻塞 ~5s**（本机实测 5016ms，TPM 存在但未配置；两台测试环境 Win32_Tpm 均不可达） | wmi 通道 tpm_probe 默认关闭（SetOption 下发），开启后接受耗时；TBS 通道在两环境均报 0x8028400F，普通权限即此结果，管理员复测仍待做 |

> **勘误（2026-09-17，T2 修正，针对 R8）**：R8 中 "SMBIOS manufacturer/serial 全空" 的读数源自
> POC `poc_smbios.cpp` 的 Type17 偏移错位——从 0x0E 起整体偏移了 2 字节，把规范中 serial@0x18
> 误读为 part。按 SMBIOS 3.x 规范修正后（`src/channels/smbios_parser.cpp`），本机实际值为
> serial=00000190（低质量厂商值，与 WMI 一致）、part=VGM5UH68…。结论不变：内存序列号不入指纹。

## 5. M1 剩余待办

1. **管理员权限复测**：TPM（TBS/WMI）、EDID 完整性——确认普通权限缺失项在提权后是否恢复；
2. **补 ≥3 台品牌物理机**（联想/戴尔/惠普优先，验证整机序列号真实值），扩展本矩阵；
3. **SATA 序列号字节序对照**（R4）：用 StorageDeviceProperty 与 WMI 对 H1 的 SATA 盘交叉验证；
4. **Win11 虚拟机（vTPM）验证 TPM 通道**。
