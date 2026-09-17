// ============================================================
// T2 SMBIOS 解析器单测：用合成表字节验证解析、去重、空槽过滤
// 覆盖 M1 矩阵 R10（VM 每 vCPU 一份 Type4 → 去重）与 Type17 规范偏移勘误
// 注意：合成结构按 SMBIOS 规范偏移构造——fmt 向量下标即规范偏移，
//       前 4 字节为 [type][len][handle:2]（len 由 Struct() 自动回填）。
// ============================================================
#include "tests/test_util.h"
#include "channels/smbios_parser.h"
#include "channels/smbios_channel.h"
#include <cstdio>
#include <string>
#include <vector>

namespace {

// fmt[0]=type, fmt[1]=len(自动回填)，fmt 下标 = SMBIOS 规范偏移
// 字符串区：每串自带 \0，区尾追加一个终止 \0（规范语义：与最后一串的 \0 构成双零）
std::vector<uint8_t> Struct(std::vector<uint8_t> fmt,
                            const std::vector<std::string>& strings) {
    fmt[1] = (uint8_t)fmt.size();
    for (const auto& s : strings) {
        fmt.insert(fmt.end(), s.begin(), s.end());
        fmt.push_back(0);
    }
    fmt.push_back(0);
    return fmt;
}

std::vector<uint8_t> BiosStruct() {
    std::vector<uint8_t> f(0x09, 0);
    f[0x00] = 0;
    f[0x04] = 1; f[0x05] = 2; f[0x08] = 3;   // vendor/version/release 串号
    return Struct(f, { "TestBIOS Inc", "1.02", "07/25/2024" });
}

std::vector<uint8_t> SysStruct() {
    std::vector<uint8_t> f(0x1B, 0);
    f[0x00] = 1;
    f[0x04] = 1; f[0x05] = 2; f[0x06] = 3; f[0x07] = 4;
    for (int i = 0; i < 16; ++i) f[0x08 + i] = (uint8_t)(0x10 + i);   // UUID
    f[0x19] = 5; f[0x1A] = 6;
    return Struct(f, { "TestMfr", "TestProduct", "1.0", "SER-1234", "SKU-9", "Fam-X" });
}

std::vector<uint8_t> BoardStruct() {
    std::vector<uint8_t> f(0x08, 0);
    f[0x00] = 2;
    f[0x04] = 1; f[0x05] = 2; f[0x06] = 3; f[0x07] = 4;
    return Struct(f, { "BoardMfr", "BoardModel", "v1", "BRD-5678" });
}

// Type4：manufacturer 串号@0x07，id 8 字节@0x08，version 串号@0x10
std::vector<uint8_t> CpuStruct(uint16_t handle, const uint8_t id[8]) {
    std::vector<uint8_t> f(0x12, 0);
    f[0x00] = 4;
    f[0x02] = (uint8_t)(handle & 0xFF); f[0x03] = (uint8_t)(handle >> 8);
    f[0x07] = 1;
    for (int i = 0; i < 8; ++i) f[0x08 + i] = id[i];
    f[0x10] = 2;
    return Struct(f, { "AMD", "Test CPU Model" });
}

// Type17（规范偏移）：size@0x0C, locator 串号@0x10, mfr@0x17, serial@0x18, part@0x1A
std::vector<uint8_t> MemoryStruct(uint16_t handle, uint16_t size_raw,
                                  const std::string& locator, const std::string& mfr,
                                  const std::string& serial, const std::string& part) {
    std::vector<uint8_t> f(0x1B, 0);
    f[0x00] = 17;
    f[0x02] = (uint8_t)(handle & 0xFF); f[0x03] = (uint8_t)(handle >> 8);
    f[0x0C] = (uint8_t)(size_raw & 0xFF);
    f[0x0D] = (uint8_t)(size_raw >> 8);
    f[0x10] = 1; f[0x17] = 2; f[0x18] = 3; f[0x1A] = 4;
    return Struct(f, { locator, mfr, serial, part });
}

std::vector<uint8_t> BuildTable(const std::vector<std::vector<uint8_t>>& structs) {
    std::vector<uint8_t> v{ 0, 3, 7, 1, 0, 0, 0, 0 };  // RawSmbios 头，版本 3.7
    for (const auto& s : structs) v.insert(v.end(), s.begin(), s.end());
    const uint32_t tableLen = (uint32_t)(v.size() - 8);
    v[4] = (uint8_t)(tableLen & 0xFF);
    v[5] = (uint8_t)((tableLen >> 8) & 0xFF);
    v[6] = (uint8_t)((tableLen >> 16) & 0xFF);
    v[7] = (uint8_t)((tableLen >> 24) & 0xFF);
    return v;
}

} // namespace

TEST(smbios_parser, full_table_fields) {
    const uint8_t id1[8] = { 0x00, 0xF4, 0x0B, 0x00, 0xFF, 0xFB, 0x8B, 0x17 };
    const uint8_t id2[8] = { 0x00, 0xF4, 0x00, 0x00, 0xFF, 0xFB, 0x8B, 0x17 };
    std::vector<uint8_t> buf = BuildTable({
        BiosStruct(), SysStruct(), BoardStruct(),
        CpuStruct(3, id1),
        CpuStruct(4, id2),                    // 同厂商同型号（仅 id 低字节异）→ 去重目标
        MemoryStruct(5, 16384, "DIMMA2", "Kingstop", "MSER-01", "PART-ABC"),
        MemoryStruct(6, 0, "DIMMB2", "", "", ""),   // 空槽 → 过滤
    });

    SmbiosData d;
    std::string err;
    CHECK(ParseSmbios(buf.data(), buf.size(), d, err));

    CHECK_EQ(d.major, 3);
    CHECK_STREQ(d.bios_vendor, "TestBIOS Inc");
    CHECK_STREQ(d.bios_version, "1.02");
    CHECK_STREQ(d.bios_release_date, "07/25/2024");
    CHECK_STREQ(d.sys_manufacturer, "TestMfr");
    CHECK_STREQ(d.sys_product, "TestProduct");
    CHECK_STREQ(d.sys_serial, "SER-1234");
    CHECK_STREQ(d.sys_sku, "SKU-9");
    CHECK_STREQ(d.sys_family, "Fam-X");
    {
        std::string uuid;
        for (int i = 0; i < 16; ++i) {
            char b[3];
            std::snprintf(b, sizeof b, "%02X", 0x10 + i);
            uuid += b;
        }
        CHECK_STREQ(d.sys_uuid_hex, uuid);
    }
    CHECK_STREQ(d.board_manufacturer, "BoardMfr");
    CHECK_STREQ(d.board_serial, "BRD-5678");

    // R10：两颗同型号 Type4 → 去重为 1
    CHECK_EQ((int)d.cpus.size(), 1);
    if (d.cpus.size() == 1) {
        CHECK_STREQ(d.cpus[0].version, "Test CPU Model");
        CHECK_STREQ(d.cpus[0].id_hex, "00F40B00FFFB8B17");
    }

    // 空槽过滤 + Type17 规范偏移（serial@0x18；POC 曾错位读 0x18 为 part）
    CHECK_EQ((int)d.mems.size(), 1);
    if (d.mems.size() == 1) {
        CHECK_EQ(d.mems[0].size_mb, 16384);
        CHECK_STREQ(d.mems[0].locator, "DIMMA2");
        CHECK_STREQ(d.mems[0].manufacturer, "Kingstop");
        CHECK_STREQ(d.mems[0].serial, "MSER-01");
        CHECK_STREQ(d.mems[0].part, "PART-ABC");
    }
}

TEST(smbios_parser, rejects_bad_buffer) {
    SmbiosData d;
    std::string err;
    CHECK(!ParseSmbios(nullptr, 0, d, err));
    uint8_t tiny[4] = { 0, 3, 7, 1 };
    CHECK(!ParseSmbios(tiny, sizeof tiny, d, err));
    // 声明长度越过缓冲边界
    uint8_t lying[8] = { 0, 3, 7, 1, 0xFF, 0, 0, 0 };
    CHECK(!ParseSmbios(lying, sizeof lying, d, err));
}

TEST(smbios_parser, survives_malformed_structures) {
    SmbiosData d;
    std::string err;

    // 截断结构：l 虚报为 0xFF，格式化区越界 → 遍历安全停止，不越界读
    {
        std::vector<uint8_t> s{ 1, 0xFF, 0, 0, 'A', 0, 0, 0 };
        auto buf = BuildTable({ s });
        CHECK(ParseSmbios(buf.data(), buf.size(), d, err));
        CHECK(d.sys_serial.empty());
    }
    // 字符串区未以双零终止 → 安全停止
    {
        std::vector<uint8_t> s{ 1, 0x08, 0, 0, 1, 2, 3, 4, 'X', 'Y', 'Z' };  // 无终止零
        auto buf = BuildTable({ s });
        CHECK(ParseSmbios(buf.data(), buf.size(), d, err));
        CHECK(d.sys_serial.empty());
    }
    // 全零表：l<4 → 立即停止
    {
        std::vector<uint8_t> buf = BuildTable({ std::vector<uint8_t>(32, 0) });
        CHECK(ParseSmbios(buf.data(), buf.size(), d, err));
        CHECK(d.bios_vendor.empty());
    }
    // l<4 的结构头 → 跳过
    {
        std::vector<uint8_t> buf = BuildTable({ std::vector<uint8_t>{ 1, 2, 0, 0 } });
        CHECK(ParseSmbios(buf.data(), buf.size(), d, err));
    }
    // 畸形结构之后的合法结构：损坏点前已解析的数据可用，损坏点即停
    {
        std::vector<uint8_t> bad{ 1, 0x30, 0, 0, 1, 2, 3, 4 };   // l 虚报越界
        auto buf = BuildTable({ bad, BoardStruct() });            // 坏结构在前
        CHECK(ParseSmbios(buf.data(), buf.size(), d, err));
        CHECK(d.board_serial.empty());                            // 遍历在坏点已停
    }
    // 合法结构在前、畸形结构在后：合法数据正常解析，遍历到坏点停止不崩溃
    {
        auto buf = BuildTable({ BoardStruct(),
                                std::vector<uint8_t>{ 1, 0x30, 0, 0, 1, 2, 3, 4 } });
        CHECK(ParseSmbios(buf.data(), buf.size(), d, err));
        CHECK_STREQ(d.board_serial, "BRD-5678");
    }
}

TEST(smbios_parser, type17_edge_values_filtered) {
    // raw=0xFFFF：规范义 unknown → 过滤；raw=0x8000：KB 粒度但 0KB → 退化为零容量 → 过滤
    auto buf = BuildTable({ MemoryStruct(5, 0xFFFF, "L1", "M", "S", "P"),
                            MemoryStruct(6, 0x8000, "L2", "M", "S", "P") });
    SmbiosData d;
    std::string err;
    CHECK(ParseSmbios(buf.data(), buf.size(), d, err));
    CHECK_EQ((int)d.mems.size(), 0);
}

TEST(smbios_parser, memory_size_kb_granularity) {
    // SMBIOS 3.1+：bit15=1 → 单位 KB；0xC000 = 0x4000KB = 16384KB = 16MB
    std::vector<uint8_t> buf = BuildTable({ MemoryStruct(5, 0xC000, "SODIMM1", "M", "S", "P") });
    SmbiosData d;
    std::string err;
    CHECK(ParseSmbios(buf.data(), buf.size(), d, err));
    CHECK_EQ((int)d.mems.size(), 1);
    if (d.mems.size() == 1) CHECK_EQ(d.mems[0].size_mb, 16);
}

TEST(smbios_channel, key_result_mapping) {
    std::vector<uint8_t> buf = BuildTable({
        BoardStruct(),
        MemoryStruct(5, 8192, "DIMMA1", "M1", "S1", "P1"),
        MemoryStruct(6, 8192, "DIMMB1", "M2", "S2", "P2"),
    });
    SmbiosData d;
    std::string err;
    CHECK(ParseSmbios(buf.data(), buf.size(), d, err));

    auto ser = SmbiosKeyResults(d, FieldKey::kBoardSerial);
    CHECK_EQ((int)ser.size(), 1);
    if (ser.size() == 1) {
        CHECK(ser[0].ok);
        CHECK_STREQ(ser[0].value, "BRD-5678");
        CHECK_EQ(ser[0].index, 0);
    }
    auto msize = SmbiosKeyResults(d, FieldKey::kMemorySize);
    CHECK_EQ((int)msize.size(), 2);
    if (msize.size() == 2) {
        CHECK_STREQ(msize[0].value, "8192");
        CHECK_EQ(msize[0].index, 0);
        CHECK_EQ(msize[1].index, 1);
    }
    auto mser = SmbiosKeyResults(d, FieldKey::kMemorySerial);
    CHECK_EQ((int)mser.size(), 2);
    if (mser.size() == 2) CHECK_STREQ(mser[1].value, "S2");

    auto unsupported = SmbiosKeyResults(d, FieldKey::kOsMachineGuid);
    CHECK(unsupported.empty());                // 非本通道字段返回空表
}
