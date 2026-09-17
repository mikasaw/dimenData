// ============================================================
// M1 POC —— SMBIOS 通道（GetSystemFirmwareTable 直读，不依赖 WMI）
// 验证矩阵：bios.* / sys.* / board.* / cpu.id / memory[*].*
// ============================================================
#include "poc_common.h"
#include <cstring>
#include <cstdio>

namespace {

#pragma pack(push, 1)
struct RawSmbios {
    BYTE  UsedCallingMethod;
    BYTE  Major;
    BYTE  Minor;
    BYTE  DmiRevision;
    DWORD Length;
    // BYTE TableData[];
};
#pragma pack(pop)

const BYTE* g_table = nullptr;
size_t      g_len   = 0;

// 取结构体字符串区第 idx 个字符串（SMBIOS 规范：索引从 1 起，0 = 未设置）
std::string Str(const BYTE* hdr, BYTE len, BYTE idx) {
    if (idx == 0) return {};
    const char* p = reinterpret_cast<const char*>(hdr + len);
    for (BYTE i = 1; *p; ++i) {
        if (i == idx) return std::string(p);
        p += std::strlen(p) + 1;
    }
    return {};
}

// 遍历指定类型的全部结构；结构边界 = 格式化区 + 双 0 结尾的字符串区
template <typename Fn>
void ForEach(BYTE want, Fn fn) {
    const BYTE* p   = g_table;
    const BYTE* end = g_table + g_len;
    while (p + 4 <= end) {
        BYTE t = p[0], l = p[1];
        if (l < 4) break;
        if (t == want) fn(p, l);
        const BYTE* s = p + l;
        while (s + 1 < end && !(s[0] == 0 && s[1] == 0)) ++s;
        if (s + 1 >= end) break;
        p = s + 2;
    }
}

} // namespace

void PocSmbios() {
    const UINT need = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (need == 0) {
        PocReport({"smbios", "channel.available", "", "GetSystemFirmwareTable(RSMB) 返回 0，通道不可用"});
        return;
    }
    std::vector<BYTE> buf(need);
    if (GetSystemFirmwareTable('RSMB', 0, buf.data(), need) == 0) {
        PocReport({"smbios", "channel.available", "", "第二次调用返回 0"});
        return;
    }
    const RawSmbios* raw = reinterpret_cast<const RawSmbios*>(buf.data());
    g_table = buf.data() + sizeof(RawSmbios);
    g_len   = raw->Length;
    PocReport({"smbios", "channel.available", "yes",
               "SMBIOS " + std::to_string(raw->Major) + "." + std::to_string(raw->Minor)});

    // Type 0 —— BIOS
    ForEach(0, [](const BYTE* p, BYTE l) {
        if (l < 0x09) return;
        PocReport({"smbios", "bios.vendor",       Str(p, l, p[0x04]), ""});
        PocReport({"smbios", "bios.version",      Str(p, l, p[0x05]), ""});
        PocReport({"smbios", "bios.release_date", Str(p, l, p[0x08]), ""});
    });

    // Type 1 —— 整机
    ForEach(1, [](const BYTE* p, BYTE l) {
        if (l < 0x08) return;
        PocReport({"smbios", "sys.manufacturer", Str(p, l, p[0x04]), ""});
        PocReport({"smbios", "sys.product",      Str(p, l, p[0x05]), ""});
        PocReport({"smbios", "sys.version",      Str(p, l, p[0x06]), ""});
        PocReport({"smbios", "sys.serial",       Str(p, l, p[0x07]), ""});
        if (l >= 0x18)  // UUID（SMBIOS 2.6+，此处按原始字节序输出）
            PocReport({"smbios", "sys.uuid", Hex(p + 0x08, 16), "原始字节序，未按 RFC4122 解析"});
        if (l >= 0x1B) {
            PocReport({"smbios", "sys.sku",    Str(p, l, p[0x19]), ""});
            PocReport({"smbios", "sys.family", Str(p, l, p[0x1A]), ""});
        }
    });

    // Type 2 —— 主板
    ForEach(2, [](const BYTE* p, BYTE l) {
        if (l < 0x08) return;
        PocReport({"smbios", "board.manufacturer", Str(p, l, p[0x04]), ""});
        PocReport({"smbios", "board.product",      Str(p, l, p[0x05]), ""});
        PocReport({"smbios", "board.version",      Str(p, l, p[0x06]), ""});
        PocReport({"smbios", "board.serial",       Str(p, l, p[0x07]), ""});
    });

    // Type 4 —— CPU
    ForEach(4, [](const BYTE* p, BYTE l) {
        if (l < 0x10) return;
        PocReport({"smbios", "cpu.manufacturer", Str(p, l, p[0x07]), ""});
        PocReport({"smbios", "cpu.id",           Hex(p + 0x08, 8),
                   "可与 WMI Win32_Processor.ProcessorId 交叉验证"});
        if (l >= 0x11)
            PocReport({"smbios", "cpu.version", Str(p, l, p[0x10]), ""});
    });

    // Type 17 —— 内存条
    int mi = 0;
    ForEach(17, [&](const BYTE* p, BYTE l) {
        char tag[24];
        snprintf(tag, sizeof tag, "memory[%d]", mi++);
        const std::string k = tag;
        if (l >= 0x0F) {
            const UINT16 sz = *(const UINT16*)(p + 0x0C);
            char b[32];
            if (sz == 0) snprintf(b, sizeof b, "%s", "0(空槽)");
            else if (sz & 0x8000) snprintf(b, sizeof b, "%u KB", sz & 0x7FFF);
            else                  snprintf(b, sizeof b, "%u MB", sz);
            PocReport({"smbios", k + ".size", b, "偏移 0x0C"});
            PocReport({"smbios", k + ".locator", Str(p, l, p[0x0E]), ""});
        }
        if (l >= 0x19) {
            PocReport({"smbios", k + ".speed_mhz",    std::to_string(*(const UINT16*)(p + 0x13)), ""});
            PocReport({"smbios", k + ".manufacturer", Str(p, l, p[0x15]), ""});
            PocReport({"smbios", k + ".serial",       Str(p, l, p[0x16]), ""});
            PocReport({"smbios", k + ".part",         Str(p, l, p[0x18]), ""});
        }
    });
}
