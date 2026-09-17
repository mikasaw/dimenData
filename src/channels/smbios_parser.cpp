#include "channels/smbios_parser.h"
#include <cstring>

namespace {

std::string Str(const uint8_t* hdr, uint8_t len, uint8_t idx) {
    if (idx == 0) return {};
    const char* p = reinterpret_cast<const char*>(hdr + len);
    for (uint8_t i = 1; *p; ++i) {
        if (i == idx) return std::string(p);
        p += std::strlen(p) + 1;
    }
    return {};
}

std::string Hex(const uint8_t* b, size_t n) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[b[i] >> 4]; s += d[b[i] & 0xF]; }
    return s;
}

uint16_t Rd16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

// 遍历指定类型的全部结构（结构边界 = 格式化区 + 双 0 结尾的字符串区）。
// 表损坏防御（T2 验收 P0 修复）：格式化区越界（p+l>end）或字符串区未以双 0
// 终止时立即停止遍历——畸形结构不可信，绝不在校验前回调 fn。
template <typename Fn>
void ForEach(const uint8_t* table, size_t len, uint8_t want, Fn fn) {
    const uint8_t* p   = table;
    const uint8_t* end = table + len;
    while (p + 4 <= end) {
        const uint8_t t = p[0], l = p[1];
        if (l < 4) break;
        if (p + l > end) break;                   // 格式化区越界
        const uint8_t* s = p + l;
        while (s + 1 < end && !(s[0] == 0 && s[1] == 0)) ++s;
        if (s + 1 >= end) break;                  // 字符串区未终止
        if (t == want) fn(p, l);
        p = s + 2;
    }
}

} // namespace

bool ParseSmbios(const uint8_t* buf, size_t len, SmbiosData& out, std::string& err) {
    // RawSmbios 头 8 字节
    if (!buf || len < 8) { err = "buffer too small"; return false; }
    out = SmbiosData{};
    out.major = buf[1];
    out.minor = buf[2];
    const uint32_t tableLen =
        (uint32_t)buf[4] | ((uint32_t)buf[5] << 8) | ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 24);
    if (8u + tableLen > len) { err = "declared table length overruns buffer"; return false; }
    const uint8_t* table = buf + 8;

    ForEach(table, tableLen, 0, [&](const uint8_t* p, uint8_t l) {
        if (l < 0x09) return;
        out.bios_vendor       = Str(p, l, p[0x04]);
        out.bios_version      = Str(p, l, p[0x05]);
        out.bios_release_date = Str(p, l, p[0x08]);
    });

    ForEach(table, tableLen, 1, [&](const uint8_t* p, uint8_t l) {
        if (l < 0x08) return;
        out.sys_manufacturer = Str(p, l, p[0x04]);
        out.sys_product      = Str(p, l, p[0x05]);
        out.sys_version      = Str(p, l, p[0x06]);
        out.sys_serial       = Str(p, l, p[0x07]);
        if (l >= 0x18) out.sys_uuid_hex = Hex(p + 0x08, 16);   // UUID，原始字节序
        if (l >= 0x1B) {
            out.sys_sku    = Str(p, l, p[0x19]);
            out.sys_family = Str(p, l, p[0x1A]);
        }
    });

    ForEach(table, tableLen, 2, [&](const uint8_t* p, uint8_t l) {
        if (l < 0x08) return;
        out.board_manufacturer = Str(p, l, p[0x04]);
        out.board_product      = Str(p, l, p[0x05]);
        out.board_version      = Str(p, l, p[0x06]);
        out.board_serial       = Str(p, l, p[0x07]);
    });

    // Type4：VM 等环境每个 vCPU 一份结构（矩阵 R10），按 (厂商, 型号) 去重，每 socket 留一份
    ForEach(table, tableLen, 4, [&](const uint8_t* p, uint8_t l) {
        if (l < 0x11) return;
        SmbiosCpu c;
        c.manufacturer = Str(p, l, p[0x07]);
        c.id_hex       = Hex(p + 0x08, 8);
        c.version      = Str(p, l, p[0x10]);
        for (const auto& ex : out.cpus)
            if (ex.manufacturer == c.manufacturer && ex.version == c.version) return;
        out.cpus.push_back(std::move(c));
    });

    // Type17（Memory Device）：规范偏移 size=0x0C, locator=0x10, speed=0x15,
    // manufacturer=0x17, serial=0x18, part=0x1A；空槽（size==0）、unknown（0xFFFF）
    // 与 KB 粒度零容量（0x8000）均视为无效过滤
    ForEach(table, tableLen, 17, [&](const uint8_t* p, uint8_t l) {
        if (l < 0x0E) return;
        const uint16_t raw = Rd16(p + 0x0C);
        if (raw == 0 || raw == 0xFFFF) return;  // 空槽 / 规范义 unknown
        SmbiosMemory m;
        if (raw & 0x8000) {                    // SMBIOS 3.1+：bit15=1 → 单位 KB
            const uint32_t kb = raw & 0x7FFF;
            m.size_mb = (int)(kb / 1024);
        } else {
            m.size_mb = raw;
        }
        if (l >= 0x11) m.locator      = Str(p, l, p[0x10]);
        if (l >= 0x19) {               // serial 位于 0x18，需 len≥0x19 才越界安全
            m.manufacturer = Str(p, l, p[0x17]);
            m.serial       = Str(p, l, p[0x18]);
        }
        if (l >= 0x1B) m.part = Str(p, l, p[0x1A]);
        if (m.size_mb <= 0) return;            // 0x8000 等退化为零容量的条目
        out.mems.push_back(std::move(m));
    });

    return true;
}
