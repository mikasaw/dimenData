// ============================================================
// WMI 通道纯函数工具（可单测）：WMI 值 → 通道统一口径的变换
// ============================================================
#pragma once
#include <string>

namespace wmi_util {

// CIM 日期时间 "20240725000000.000000+000" → "2024-07-25"（矩阵 R12）。
// 输入不足 8 位数字部分时返回空串。
std::string DatetimeToIsoDate(const std::string& cim_datetime);

// MAC 统一为无分隔符大写十六进制（与 native 通道一致，供 CONSENSUS 比较）
std::string MacNormalize(const std::string& mac);

// WMI Capacity（字节数字符串）→ MB 字符串（与 smbios MemorySize 口径一致）。
// 非数字输入返回空串。
std::string CapacityBytesToMb(const std::string& bytes);

// R6：按 PNP 设备实例 ID 判"疑似物理网卡"——仅 PCI/USB 总线前缀视为物理，
// ROOT\（软件设备，VMware VMnet 属此类）、SWD\、ACPI\ 等一律排除。
// id 大小写不敏感；空串返回 false（无法判定，保守排除）。
bool NicPnpLikelyPhysical(const std::string& pnp_device_id);

// R6（显卡）：按 PNP 设备实例 ID 判"疑似物理显卡"——仅 PCI 总线前缀视为物理。
// 真显卡（独显/核显）均为 PCI\VEN_*；虚拟显示适配器（GameViewer 的
// ROOT\DISPLAY、Microsoft Basic Display 的 ROOT\BasicDisplay、间接显示驱动等）
// 为 ROOT\/SWD\ 软件设备，一律排除。大小写不敏感；空串返回 false。
bool GpuPnpLikelyPhysical(const std::string& pnp_device_id);

// R6（显卡）：名称黑名单兜底——个别虚拟显示驱动可能挂在 PCI 总线下，
// 名称含虚拟显示关键词时排除。name 大小写不敏感。
bool GpuNameLooksVirtual(const std::string& name);

} // namespace wmi_util
