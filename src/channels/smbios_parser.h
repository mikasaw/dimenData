// ============================================================
// SMBIOS 表解析器（纯函数，与系统 API 解耦，便于用录制字节做单测）
// 偏移依据 SMBIOS 3.x 规范；Type17 偏移在 M1 POC 中曾错位 2 字节，此处为修正版
// （见 docs/M1-POC-采集项可用性矩阵.md §4 R8 勘误）。
// ============================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct SmbiosCpu {
    std::string manufacturer;
    std::string version;   // 型号串，如 "Example CPU 9000X 8-Core Processor"
    std::string id_hex;    // Type4 偏移 0x08 的 8 字节，原始十六进制（大写）
};

struct SmbiosMemory {
    int         size_mb = 0;
    std::string locator;
    std::string manufacturer;
    std::string serial;
    std::string part;
};

// 解析产物：纯数据，通道层再映射为 FieldResult
struct SmbiosData {
    int major = 0, minor = 0;

    std::string bios_vendor, bios_version, bios_release_date, bios_serial;
    std::string sys_manufacturer, sys_product, sys_version, sys_serial;
    std::string sys_uuid_hex;   // Type1 偏移 0x08 的 16 字节，原始字节序十六进制（大写）
    std::string sys_sku, sys_family;
    std::string board_manufacturer, board_product, board_version, board_serial;

    std::vector<SmbiosCpu>    cpus;   // 已按 (厂商, 型号) 去重，每 socket 保留一份（矩阵 R10）
    std::vector<SmbiosMemory> mems;   // 已过滤空槽（size==0）
};

// 解析 GetSystemFirmwareTable('RSMB') 返回的完整缓冲：
//   [UsedCallingMethod][Major][Minor][DmiRev][Length:u32][表数据...]
// 失败返回 false 并写 err；占位串（"None" 等）原样保留，由归并层黑名单处理（矩阵 R3）。
bool ParseSmbios(const uint8_t* buf, size_t len, SmbiosData& out, std::string& err);
