// ============================================================
// M1 POC —— 注册表通道
// 验证矩阵：os.machine_guid / os.product_id / os.version / monitor[*](EDID)
// ============================================================
#include "poc_common.h"

namespace {

std::string RegStr(HKEY root, const char* sub, const char* name, REGSAM extra = 0) {
    HKEY k;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ | extra, &k) != ERROR_SUCCESS) return {};
    char buf[1024];
    DWORD sz = sizeof(buf), type = 0;
    std::string out;
    if (RegQueryValueExA(k, name, nullptr, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ))
        out.assign(buf, strnlen(buf, sz));
    RegCloseKey(k);
    return out;
}

std::string RegDw(HKEY root, const char* sub, const char* name, bool* ok = nullptr) {
    HKEY k;
    if (ok) *ok = false;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return {};
    DWORD v = 0, sz = sizeof(v), type = 0;
    std::string out;
    if (RegQueryValueExA(k, name, nullptr, &type, (LPBYTE)&v, &sz) == ERROR_SUCCESS &&
        type == REG_DWORD) {
        if (ok) *ok = true;
        out = std::to_string(v);
    }
    RegCloseKey(k);
    return out;
}

// 枚举 DISPLAY\厂商\实例\Device Parameters\EDID，解析 EDID 头部固定字段
void EnumEdid() {
    HKEY disp;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
                      0, KEY_READ, &disp) != ERROR_SUCCESS) {
        PocReport({"registry", "monitor[0].vendor_code", "", "DISPLAY 枚举键不存在"});
        return;
    }
    char vendor[256];
    DWORD vlen = sizeof(vendor), vi = 0;
    int mon = 0;
    while (RegEnumKeyExA(disp, vi++, vendor, &vlen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        vlen = sizeof(vendor);
        HKEY vk;
        if (RegOpenKeyExA(disp, vendor, 0, KEY_READ, &vk) != ERROR_SUCCESS) continue;
        char inst[256];
        DWORD ilen = sizeof(inst), ii = 0;
        while (RegEnumKeyExA(vk, ii++, inst, &ilen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            ilen = sizeof(inst);
            const std::string dp = std::string(vendor) + "\\" + inst + "\\Device Parameters";
            HKEY pk;
            if (RegOpenKeyExA(disp, dp.c_str(), 0, KEY_READ, &pk) != ERROR_SUCCESS) continue;
            BYTE edid[512];
            DWORD sz = sizeof(edid), t = 0;
            // EDID 固定头 00 FF FF FF FF FF FF 00
            if (RegQueryValueExA(pk, "EDID", nullptr, &t, edid, &sz) == ERROR_SUCCESS &&
                sz >= 128 && edid[0] == 0x00 && edid[1] == 0xFF) {
                const WORD m    = (WORD)((edid[8] << 8) | edid[9]);
                const char mc[] = { (char)('A' + ((m >> 10) & 0x1F) - 1),
                                    (char)('A' + ((m >> 5) & 0x1F) - 1),
                                    (char)('A' + (m & 0x1F) - 1), 0 };
                const WORD  prod = (WORD)(edid[10] | (edid[11] << 8));
                const DWORD ser  = (DWORD)edid[12] | ((DWORD)edid[13] << 8) |
                                   ((DWORD)edid[14] << 16) | ((DWORD)edid[15] << 24);
                const std::string k = "monitor[" + std::to_string(mon) + "]";
                PocReport({"registry", k + ".vendor_code", mc, "EDID 头部 3 字母厂码"});
                PocReport({"registry", k + ".product_id", std::to_string(prod),
                           "0x" + Hex((const BYTE*)&prod, 2)});
                PocReport({"registry", k + ".serial_int", std::to_string(ser), "EDID 整数序列号"});
            }
            RegCloseKey(pk);
            ++mon;
        }
        RegCloseKey(vk);
    }
    RegCloseKey(disp);
}

} // namespace

void PocRegistry() {
    // OS 标识（重装系统会变 —— 正式版仅低权重参与指纹）
    std::string guid = RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography",
                              "MachineGuid", KEY_WOW64_64KEY);
    PocReport({"registry", "os.machine_guid", guid, guid.empty() ? "未找到" : "64 位视图"});

    const char* cv = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    PocReport({"registry", "os.product_id",       RegStr(HKEY_LOCAL_MACHINE, cv, "ProductId", KEY_WOW64_64KEY), ""});
    PocReport({"registry", "os.display_version",  RegStr(HKEY_LOCAL_MACHINE, cv, "DisplayVersion", KEY_WOW64_64KEY), ""});
    PocReport({"registry", "os.build",            RegStr(HKEY_LOCAL_MACHINE, cv, "CurrentBuildNumber", KEY_WOW64_64KEY), ""});
    bool ok = false;
    std::string inst = RegDw(HKEY_LOCAL_MACHINE, cv, "InstallDate", &ok);
    PocReport({"registry", "os.install_date", ok ? inst : "", "Unix 时间戳"});

    // SecureBoot：只采集，不入指纹
    std::string sb = RegDw(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                           "UEFISecureBoot", &ok);
    PocReport({"registry", "os.secure_boot", ok ? sb : "", ok ? "1=启用" : "键不存在（Legacy/未启用）"});

    EnumEdid();
}
