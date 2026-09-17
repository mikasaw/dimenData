// ============================================================
// T3 registry 通道单测：EDID 解析（合成 EDID 字节）
// ============================================================
#include "tests/test_util.h"
#include "channels/registry_parser.h"
#include <cstring>
#include <vector>

namespace {

// 合成 128 字节 EDID：厂码 3 字母、product LE、serial LE，其余零
std::vector<uint8_t> MakeEdid(const char v[3], uint16_t product, uint32_t serial) {
    std::vector<uint8_t> e(128, 0);
    e[0] = 0x00; e[1] = 0xFF; e[2] = 0xFF; e[3] = 0xFF;
    e[4] = 0xFF; e[5] = 0xFF; e[6] = 0xFF; e[7] = 0x00;
    const uint16_t m = (uint16_t)(((v[0] - 'A' + 1) << 10) | ((v[1] - 'A' + 1) << 5) |
                                  (v[2] - 'A' + 1));
    e[8]  = (uint8_t)(m >> 8);
    e[9]  = (uint8_t)(m & 0xFF);
    e[10] = (uint8_t)(product & 0xFF);
    e[11] = (uint8_t)(product >> 8);
    e[12] = (uint8_t)(serial & 0xFF);
    e[13] = (uint8_t)((serial >> 8) & 0xFF);
    e[14] = (uint8_t)((serial >> 16) & 0xFF);
    e[15] = (uint8_t)((serial >> 24) & 0xFF);
    return e;
}

} // namespace

TEST(registry_edid, parse_header_fields) {
    auto e = MakeEdid("DEL", 0xE6D0, 0x304D5D05u);
    EdidInfo info;
    CHECK(ParseEdid(e.data(), e.size(), info));
    CHECK_STREQ(info.vendor_code, "DEL");
    CHECK_EQ((int)info.product_id, 0xE6D0);
    // CHECK_EQ 仅支持算术窄类型，uint32 用整数比较
    CHECK((int64_t)info.serial_int == (int64_t)0x304D5D05);

    auto e2 = MakeEdid("AUS", 9635, 16843009);
    EdidInfo i2;
    CHECK(ParseEdid(e2.data(), e2.size(), i2));
    CHECK_STREQ(i2.vendor_code, "AUS");
    CHECK_EQ((int)i2.product_id, 9635);
    CHECK_EQ((int)i2.serial_int, 16843009);   // 0x01010101
}

TEST(registry_edid, rejects_bad_input) {
    EdidInfo info;
    CHECK(!ParseEdid(nullptr, 0, info));
    auto e = MakeEdid("DEL", 1, 2);
    CHECK(!ParseEdid(e.data(), 127, info));          // 不足 128
    e[1] = 0xFE;                                     // 头部损坏
    CHECK(!ParseEdid(e.data(), e.size(), info));
}

TEST(registry_edid, reserved_letter_maps_to_unk) {
    // 5bit 厂码含保留值 0（'@'）→ 厂码记 "unk"，其余字段照常解析
    auto e = MakeEdid("@US", 7, 8);
    EdidInfo info;
    CHECK(ParseEdid(e.data(), e.size(), info));
    CHECK_STREQ(info.vendor_code, "unk");
    CHECK_EQ((int)info.product_id, 7);
    CHECK_EQ((int)info.serial_int, 8);
}
