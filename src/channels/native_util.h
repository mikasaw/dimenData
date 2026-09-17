// ============================================================
// Native 通道纯函数工具（可单测，不触系统 API）
// ============================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace native_util {

// CPUID leaf0 返回的 EBX/EDX/ECX → 厂商标识串（如 "GenuineIntel"/"AuthenticAMD"）
std::string CpuVendorFromLeaf0(int ebx, int edx, int ecx);

// CPUID 0x80000002..0x80000004 的 3 组寄存器 → 品牌串（调用方负责 Trim）
std::string CpuBrandFromLeaves(const int leaves[3][4]);

// CPUID leaf1 的 EAX/EDX → 处理器 ID 十六进制串（大写，EDX:EAX 顺序，与 WMI 格式一致）。
// 注意 R1/R2：与 SMBIOS Type4 是字节序差异，且低字节含 APIC ID 随拓扑变化——
// 归一化在指纹/归并层完成，此处输出原始格式。
std::string CpuIdFromLeaf1(int eax, int edx);

// 物理网卡初筛（矩阵 R6/R7）：回环/隧道/描述含虚拟关键字/描述为空 → false。
// desc_lower 须为小写描述串。此为"疑似物理"启发式，PNP 级精判属后续任务。
bool NicLikelyPhysical(unsigned if_type, const std::string& desc_lower);

// —— GPU UUID（nvidia-smi）——

struct NvidiaGpu {
    std::string index;   // nvidia-smi 的 GPU 索引（十进制）
    std::string name;    // 型号串（可能含逗号，解析时按"首字段=index、末字段=uuid"切分）
    std::string uuid;    // 形如 GPU-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx 或 MIG-...
};

// 解析 `nvidia-smi --query-gpu=index,name,uuid --format=csv,noheader` 输出。
// 容错：跳过空行/字段不足/首字段非数字的行；name 允许含逗号。
std::vector<NvidiaGpu> ParseNvidiaSmiUuidCsv(const std::string& text);

// 校验 NVIDIA GPU UUID 形态（GPU- 或 MIG- 前缀 + 8-4-4-4-12 十六进制）。
// 排除 nvidia-smi 在无 UUID 环境输出的占位值（[N/A]、N/A、空、纯 0）。
bool IsNvidiaGpuUuid(const std::string& s);

} // namespace native_util
