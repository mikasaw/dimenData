#include <windows.h>
#include "channels/smbios_channel.h"
#include "core/channel_registry.h"   // REGISTER_CHANNEL 宏
#include <cstdio>
#include <vector>

namespace {

std::vector<uint8_t> ReadFirmwareTable(std::string& err) {
    const UINT need = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (need == 0) { err = "GetSystemFirmwareTable(RSMB) returned 0"; return {}; }
    std::vector<uint8_t> buf(need);
    if (GetSystemFirmwareTable('RSMB', 0, buf.data(), need) == 0) {
        err = "GetSystemFirmwareTable(RSMB) second call returned 0";
        return {};
    }
    return buf;
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

} // namespace

bool SmbiosChannel::Available() {
    return EnsureParsed();
}

bool SmbiosChannel::EnsureParsed() {
    std::lock_guard<std::mutex> lk(mu_);
    if (parsed_) return error_.empty();
    parsed_ = true;
    std::vector<uint8_t> buf = ReadFirmwareTable(error_);
    if (buf.empty()) return false;
    if (!ParseSmbios(buf.data(), buf.size(), data_, error_)) return false;
    return true;
}

std::vector<FieldKey> SmbiosChannel::SupportedFields() const {
    return {
        FieldKey::kBiosVendor, FieldKey::kBiosVersion, FieldKey::kBiosReleaseDate,
        // bios.serial 不在此声明：SMBIOS Type0 无序列号，该字段由 wmi 通道供给
        FieldKey::kSysManufacturer, FieldKey::kSysProduct, FieldKey::kSysVersion,
        FieldKey::kSysSerial, FieldKey::kSysUuid, FieldKey::kSysSku, FieldKey::kSysFamily,
        FieldKey::kBoardManufacturer, FieldKey::kBoardProduct, FieldKey::kBoardVersion,
        FieldKey::kBoardSerial,
        FieldKey::kCpuManufacturer, FieldKey::kCpuName, FieldKey::kCpuId,
        FieldKey::kMemorySize, FieldKey::kMemorySerial, FieldKey::kMemoryPart,
        FieldKey::kMemoryLocator,
    };
}

std::vector<FieldResult> SmbiosChannel::Collect(FieldKey key) {
    if (!EnsureParsed())
        return { Res(key, 0, "", ("smbios unavailable: " + error_).c_str()) };
    return SmbiosKeyResults(data_, key);
}

std::vector<FieldResult> SmbiosKeyResults(const SmbiosData& d, FieldKey key) {
    char note[64];
    std::snprintf(note, sizeof note, "SMBIOS %d.%d", d.major, d.minor);

    std::vector<FieldResult> out;
    switch (key) {
    case FieldKey::kBiosVendor:      out.push_back(Res(key, 0, d.bios_vendor, note)); break;
    case FieldKey::kBiosVersion:     out.push_back(Res(key, 0, d.bios_version, note)); break;
    case FieldKey::kBiosReleaseDate: out.push_back(Res(key, 0, d.bios_release_date, note)); break;
    case FieldKey::kBiosSerial:      out.push_back(Res(key, 0, d.bios_serial, note)); break;

    case FieldKey::kSysManufacturer: out.push_back(Res(key, 0, d.sys_manufacturer, note)); break;
    case FieldKey::kSysProduct:      out.push_back(Res(key, 0, d.sys_product, note)); break;
    case FieldKey::kSysVersion:      out.push_back(Res(key, 0, d.sys_version, note)); break;
    case FieldKey::kSysSerial:       out.push_back(Res(key, 0, d.sys_serial, note)); break;
    case FieldKey::kSysUuid:         out.push_back(Res(key, 0, d.sys_uuid_hex, note)); break;
    case FieldKey::kSysSku:          out.push_back(Res(key, 0, d.sys_sku, note)); break;
    case FieldKey::kSysFamily:       out.push_back(Res(key, 0, d.sys_family, note)); break;

    case FieldKey::kBoardManufacturer: out.push_back(Res(key, 0, d.board_manufacturer, note)); break;
    case FieldKey::kBoardProduct:      out.push_back(Res(key, 0, d.board_product, note)); break;
    case FieldKey::kBoardVersion:      out.push_back(Res(key, 0, d.board_version, note)); break;
    case FieldKey::kBoardSerial:       out.push_back(Res(key, 0, d.board_serial, note)); break;

    case FieldKey::kCpuManufacturer:
        for (size_t i = 0; i < d.cpus.size(); ++i)
            out.push_back(Res(key, (int)i, d.cpus[i].manufacturer, note));
        break;
    case FieldKey::kCpuName:
        for (size_t i = 0; i < d.cpus.size(); ++i)
            out.push_back(Res(key, (int)i, d.cpus[i].version, note));
        break;
    case FieldKey::kCpuId:
        for (size_t i = 0; i < d.cpus.size(); ++i)
            out.push_back(Res(key, (int)i, d.cpus[i].id_hex, note));
        break;

    case FieldKey::kMemorySize:
        for (size_t i = 0; i < d.mems.size(); ++i) {
            char b[32];
            std::snprintf(b, sizeof b, "%d", d.mems[i].size_mb);
            out.push_back(Res(key, (int)i, b, "单位 MB"));
        }
        break;
    case FieldKey::kMemorySerial:
        for (size_t i = 0; i < d.mems.size(); ++i)
            out.push_back(Res(key, (int)i, d.mems[i].serial, note));
        break;
    case FieldKey::kMemoryPart:
        for (size_t i = 0; i < d.mems.size(); ++i)
            out.push_back(Res(key, (int)i, d.mems[i].part, note));
        break;
    case FieldKey::kMemoryLocator:
        for (size_t i = 0; i < d.mems.size(); ++i)
            out.push_back(Res(key, (int)i, d.mems[i].locator, note));
        break;

    default:
        break;  // 非本通道字段：返回空表，调度器按 SupportedFields 不会派发
    }
    return out;
}

REGISTER_CHANNEL(SmbiosChannel)
