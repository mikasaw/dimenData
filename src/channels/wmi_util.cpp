#include "channels/wmi_util.h"

namespace wmi_util {

std::string DatetimeToIsoDate(const std::string& cim) {
    if (cim.size() < 8) return {};
    for (int i = 0; i < 8; ++i)
        if (cim[i] < '0' || cim[i] > '9') return {};
    // yyyymmdd → yyyy-mm-dd
    std::string out;
    out.reserve(10);
    out.append(cim, 0, 4);
    out += '-';
    out.append(cim, 4, 2);
    out += '-';
    out.append(cim, 6, 2);
    return out;
}

std::string MacNormalize(const std::string& mac) {
    std::string out;
    out.reserve(mac.size());
    for (char c : mac) {
        if (c == ':' || c == '-' || c == ' ') continue;
        out += (c >= 'a' && c <= 'f') ? (char)(c - 'a' + 'A') : c;
    }
    return out;
}

std::string CapacityBytesToMb(const std::string& bytes) {
    if (bytes.empty() || bytes.size() > 12) return {};   // 空/超长（防 ULL 回绕）
    unsigned long long v = 0;
    for (char c : bytes) {
        if (c < '0' || c > '9') return {};
        v = v * 10 + (unsigned long long)(c - '0');
    }
    return std::to_string(v / (1024ULL * 1024ULL));
}

namespace {

// PNP ID 归一：去空白 + 小写
std::string NormalizeId(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == ' ' || c == '\t') continue;
        out += (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    return out;
}

std::string Lower(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out += (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    return out;
}

} // namespace

bool NicPnpLikelyPhysical(const std::string& pnp_device_id) {
    const std::string id = NormalizeId(pnp_device_id);
    if (id.rfind("pci\\", 0) == 0) return true;
    if (id.rfind("usb\\", 0) == 0) return true;
    return false;   // ROOT\ / SWD\ / ACPI\ / 空串等，保守排除
}

bool GpuPnpLikelyPhysical(const std::string& pnp_device_id) {
    const std::string id = NormalizeId(pnp_device_id);
    // 仅 PCI 白名单：真显卡全在 PCI 总线；ROOT\DISPLAY（GameViewer）、
    // ROOT\BasicDisplay（Microsoft 基本显示适配器）等软件设备被排除
    return id.rfind("pci\\", 0) == 0;
}

bool GpuNameLooksVirtual(const std::string& name) {
    const std::string n = Lower(name);
    static const char* kVirtualNames[] = {
        "virtual display", "virtual adapter", "indirect display", "gameviewer",
        "usbmmidd", "iddsampledriver", "remote display", "basic display",
        "parsec", "spacedesk", "mirror driver", "displaylink",
    };
    for (const char* k : kVirtualNames)
        if (n.find(k) != std::string::npos) return true;
    return false;
}

} // namespace wmi_util
