#include "channels/registry_parser.h"
#include <cstring>

bool ParseEdid(const uint8_t* edid, size_t len, EdidInfo& out) {
    static const uint8_t kHeader[8] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    if (!edid || len < 128 || std::memcmp(edid, kHeader, 8) != 0) return false;
    out = EdidInfo{};
    const uint16_t m = (uint16_t)((edid[8] << 8) | edid[9]);
    const uint8_t c1 = (m >> 10) & 0x1F, c2 = (m >> 5) & 0x1F, c3 = m & 0x1F;
    if (c1 == 0 || c2 == 0 || c3 == 0) {
        // 5bit 保留值 0 非法（幽灵/损坏 EDID 常见），厂码记为 "unk"
        std::memcpy(out.vendor_code, "unk", 4);
    } else {
        out.vendor_code[0] = (char)('A' + c1 - 1);
        out.vendor_code[1] = (char)('A' + c2 - 1);
        out.vendor_code[2] = (char)('A' + c3 - 1);
        out.vendor_code[3] = '\0';
    }
    out.product_id = (uint16_t)(edid[10] | (edid[11] << 8));
    out.serial_int = (uint32_t)edid[12] | ((uint32_t)edid[13] << 8) |
                     ((uint32_t)edid[14] << 16) | ((uint32_t)edid[15] << 24);
    return true;
}
