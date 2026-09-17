#include <windows.h>
#include "channels/registry_channel.h"
#include "core/channel_registry.h"   // REGISTER_CHANNEL 宏
#include <string>

#pragma comment(lib, "advapi32")     // RegOpenKeyExA / RegQueryValueExA / RegEnumKeyExA

namespace {

std::string RegStr(HKEY root, const char* sub, const char* name, bool& ok, REGSAM extra = 0) {
    HKEY k;
    ok = false;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ | extra, &k) != ERROR_SUCCESS) return {};
    char buf[1024];
    DWORD sz = sizeof(buf), type = 0;
    std::string out;
    if (RegQueryValueExA(k, name, nullptr, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        out.assign(buf, strnlen(buf, sz));
        ok = true;
    }
    RegCloseKey(k);
    return out;
}

// 读 DWORD；返回 false 区分“键/值不存在”与值本身
bool RegDw(HKEY root, const char* sub, const char* name, DWORD& v) {
    HKEY k;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    DWORD sz = sizeof(v), type = 0;
    const bool ok = RegQueryValueExA(k, name, nullptr, &type, (LPBYTE)&v, &sz) == ERROR_SUCCESS &&
                    type == REG_DWORD;
    RegCloseKey(k);
    return ok;
}

FieldResult Res(FieldKey key, int index, const std::string& v, const char* note = "") {
    FieldResult r;
    r.key   = key;
    r.index = index;
    r.value = v;
    r.note  = note;
    r.ok    = !v.empty();
    return r;
}

// 字符串注册表字段统一入口：读不到时 ok=false 且 note 写明原因（验收 P2 一致性）
FieldResult OsStr(FieldKey key, const char* sub, const char* name, const char* note = "") {
    bool ok = false;
    std::string v = RegStr(HKEY_LOCAL_MACHINE, sub, name, ok, KEY_WOW64_64KEY);
    if (!ok) return Res(key, 0, "", "注册表值缺失");
    return Res(key, 0, v, note);
}

std::vector<EdidInfo> EnumEdids() {
    std::vector<EdidInfo> out;
    HKEY disp;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
                      0, KEY_READ, &disp) != ERROR_SUCCESS)
        return out;
    char vendor[256];
    DWORD vlen = sizeof(vendor), vi = 0;
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
            if (RegQueryValueExA(pk, "EDID", nullptr, &t, edid, &sz) == ERROR_SUCCESS &&
                t == REG_BINARY) {
                EdidInfo info;
                if (ParseEdid(edid, sz, info)) out.push_back(info);
            }
            RegCloseKey(pk);
        }
        RegCloseKey(vk);
    }
    RegCloseKey(disp);
    return out;
}

} // namespace

bool RegistryChannel::Available() { return true; }   // HKLM 只读恒可用

const std::vector<EdidInfo>& RegistryChannel::Edids() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!edids_loaded_) {
        edids_ = EnumEdids();
        edids_loaded_ = true;
    }
    return edids_;
}

std::vector<FieldKey> RegistryChannel::SupportedFields() const {
    return {
        FieldKey::kOsMachineGuid, FieldKey::kOsProductId, FieldKey::kOsDisplayVersion,
        FieldKey::kOsBuild, FieldKey::kOsInstallDate, FieldKey::kOsSecureBoot,
        FieldKey::kMonitorVendorCode, FieldKey::kMonitorProductId, FieldKey::kMonitorSerial,
    };
}

std::vector<FieldResult> RegistryChannel::Collect(FieldKey key) {
    std::vector<FieldResult> out;
    switch (key) {
    case FieldKey::kOsMachineGuid:
        out.push_back(OsStr(key, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid",
                            "重装系统会变"));
        break;
    case FieldKey::kOsProductId:
        out.push_back(OsStr(key, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId"));
        break;
    case FieldKey::kOsDisplayVersion:
        out.push_back(OsStr(key, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                            "DisplayVersion"));
        break;
    case FieldKey::kOsBuild:
        out.push_back(OsStr(key, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                            "CurrentBuildNumber"));
        break;
    case FieldKey::kOsInstallDate: {
        DWORD v = 0;
        if (RegDw(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                  "InstallDate", v))
            out.push_back(Res(key, 0, std::to_string(v), "Unix 时间戳"));
        else
            out.push_back(Res(key, 0, "", "InstallDate 不存在"));
        break;
    }
    case FieldKey::kOsSecureBoot: {
        DWORD v = 0;
        if (RegDw(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                  "UEFISecureBoot", v))
            out.push_back(Res(key, 0, std::to_string(v), "1=启用；只采集不入指纹"));
        else
            out.push_back(Res(key, 0, "", "键不存在（Legacy/未启用）"));
        break;
    }
    case FieldKey::kMonitorVendorCode: {
        const auto& eds = Edids();
        for (size_t i = 0; i < eds.size(); ++i)
            out.push_back(Res(key, (int)i, eds[i].vendor_code, "EDID 头部 3 字母厂码"));
        break;
    }
    case FieldKey::kMonitorProductId: {
        const auto& eds = Edids();
        for (size_t i = 0; i < eds.size(); ++i)
            out.push_back(Res(key, (int)i, std::to_string(eds[i].product_id)));
        break;
    }
    case FieldKey::kMonitorSerial: {
        const auto& eds = Edids();
        for (size_t i = 0; i < eds.size(); ++i)
            out.push_back(Res(key, (int)i, std::to_string(eds[i].serial_int),
                              "EDID 整数序列号；不入指纹"));
        break;
    }
    default:
        break;
    }
    return out;
}

REGISTER_CHANNEL(RegistryChannel)
