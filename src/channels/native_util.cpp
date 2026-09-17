#include "channels/native_util.h"
#include "core/textutil.h"
#include <cstdio>

namespace native_util {

std::string CpuVendorFromLeaf0(int ebx, int edx, int ecx) {
    // 每个寄存器按高字节在前展开：EBX|EDX|ECX 拼出 "GenuineIntel"/"AuthenticAMD"
    char v[13] = {};
    const int regs[3] = { ebx, edx, ecx };
    for (int r = 0; r < 3; ++r)
        for (int i = 0; i < 4; ++i)
            v[r * 4 + i] = (char)((regs[r] >> (8 * (3 - i))) & 0xFF);
    return textutil::Trim(v);
}

std::string CpuBrandFromLeaves(const int leaves[3][4]) {
    char b[49] = {};
    for (int l = 0; l < 3; ++l)
        for (int r = 0; r < 4; ++r)
            for (int i = 0; i < 4; ++i)
                b[(l * 4 + r) * 4 + i] = (char)((leaves[l][r] >> (i * 8)) & 0xFF);
    return textutil::Trim(b);
}

std::string CpuIdFromLeaf1(int eax, int edx) {
    // 与 WMI Win32_Processor.ProcessorId 呈现一致：EDX:EAX 各 8 位大写十六进制。
    // R1/R2 的字节序归一与 APIC 字节屏蔽在归并/指纹层完成。
    char b[17] = {};
    std::snprintf(b, sizeof b, "%08X%08X", (unsigned)edx, (unsigned)eax);
    return b;
}

namespace {

// 去首尾空白
std::string TrimWs(const std::string& s) {
    const char* ws = " \t\r\n";
    const size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos) return {};
    const size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
}

} // namespace

std::vector<NvidiaGpu> ParseNvidiaSmiUuidCsv(const std::string& text) {
    std::vector<NvidiaGpu> out;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t eol = text.find('\n', pos);
        const std::string line = TrimWs(text.substr(pos, eol == std::string::npos
                                                           ? std::string::npos : eol - pos));
        pos = (eol == std::string::npos) ? text.size() + 1 : eol + 1;
        if (line.empty()) continue;

        // 切分：首字段=index、末字段=uuid、中间全部为 name（name 可能含逗号）
        const size_t first = line.find(',');
        if (first == std::string::npos) continue;
        const size_t last = line.rfind(',');
        if (last == first) continue;   // 至少三字段
        const std::string idx  = TrimWs(line.substr(0, first));
        const std::string uuid = TrimWs(line.substr(last + 1));
        const std::string name = TrimWs(line.substr(first + 1, last - first - 1));
        if (idx.empty() || idx.find_first_not_of("0123456789") != std::string::npos) continue;
        if (!IsNvidiaGpuUuid(uuid)) continue;   // 无 UUID（[N/A] 等）的行整体跳过
        out.push_back(NvidiaGpu{ idx, name, uuid });
    }
    return out;
}

bool IsNvidiaGpuUuid(const std::string& s) {
    if (s.rfind("GPU-", 0) != 0 && s.rfind("MIG-", 0) != 0) return false;
    // 形态：前缀 + 5 组十六进制（8-4-4-4-12），组间 '-'，长度恰为 4+36
    const std::string hex = s.substr(4);
    if (hex.size() != 36) return false;
    static const size_t kGroupLen[5] = { 8, 4, 4, 4, 12 };
    size_t i = 0;
    for (int g = 0; g < 5; ++g) {
        for (size_t k = 0; k < kGroupLen[g]; ++k, ++i) {
            const char c = hex[i];
            const bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                               (c >= 'A' && c <= 'F');
            if (!isHex) return false;
        }
        if (g < 4) {
            if (hex[i] != '-') return false;
            ++i;
        }
    }
    return true;
}

bool NicLikelyPhysical(unsigned if_type, const std::string& desc_lower) {
    // IANA ifType：24 软件回环、131 隧道
    if (if_type == 24 || if_type == 131) return false;
    if (desc_lower.empty()) return false;   // 无法判定，保守排除
    static const char* kVirtual[] = {
        "virtual", "vmware", "hyper-v", "vethernet", "tap", "loopback",
        "wan miniport", "bluetooth", "vpn", "teredo", "vbox", "wi-fi direct",
        "microsoft kernel debug", "kdnic", "km-test", "virtualbox",
    };
    for (const char* k : kVirtual)
        if (desc_lower.find(k) != std::string::npos) return false;
    return true;
}

} // namespace native_util
