// ============================================================
// EDID 解析（纯函数，可单测）
// 输入为注册表 DISPLAY\...\Device Parameters\EDID 的 128+ 字节块
// ============================================================
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

struct EdidInfo {
    char        vendor_code[4];   // 3 字母厂码 + NUL，如 "AUS"；5bit 保留值 0 时为 "unk"
    uint16_t    product_id = 0;   // LE
    uint32_t    serial_int = 0;   // 整数序列号（描述符串序列号不在本结构）
};

// 校验固定头 00 FF FF FF FF FF FF 00 并解析头部字段；
// len < 128 或头部不符返回 false
bool ParseEdid(const uint8_t* edid, size_t len, EdidInfo& out);
