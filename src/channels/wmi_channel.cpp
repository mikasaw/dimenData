#define _WIN32_DCOM
#include <windows.h>
#include "channels/wmi_channel.h"
#include "channels/wmi_util.h"
#include "core/channel_registry.h"   // REGISTER_CHANNEL 宏
#include "core/textutil.h"
#include <comdef.h>
#include <Wbemidl.h>
#include <cstdio>
#include <utility>
#include <vector>

#pragma comment(lib, "wbemuuid")

namespace {

// 字段 → (WQL, 属性名, 可选值变换)。表驱动，新增字段只改本表（开发计划 §3.2）。
// 行级过滤规则（R6）：虚拟设备不进清单
enum class RowFilter {
    None,
    NicPnp,       // 网卡：PCI/USB 总线白名单
    GpuVirtual,   // 显卡：PCI 总线白名单 + 名称黑名单
};

// 同一 WQL 的多个字段共享一次类查询（见 WmiChannel 头注释）。
struct WmiSpec {
    FieldKey      key;
    const wchar_t* wql;
    const wchar_t* property;
    std::string (*transform)(const std::string&) = nullptr;  // 通道口径变换
    bool           indexed = false;   // 多实例类（处理器/内存/磁盘/网卡）
    const char*    note = "";
    RowFilter      filter = RowFilter::None;   // 行级虚拟设备过滤
    const wchar_t* key_prop = nullptr;         // 实例对齐键（如磁盘 Index），
                                               // 供 ConsensusAligned 逐盘对齐
};

const WmiSpec kSpecs[] = {
    // 整机（ComputerSystemProduct 与 SMBIOS Type1 同源）
    { FieldKey::kSysManufacturer, L"SELECT Vendor FROM Win32_ComputerSystemProduct", L"Vendor" },
    { FieldKey::kSysProduct,      L"SELECT Name FROM Win32_ComputerSystemProduct", L"Name" },
    { FieldKey::kSysVersion,      L"SELECT Version FROM Win32_ComputerSystemProduct", L"Version" },
    { FieldKey::kSysSerial,       L"SELECT IdentifyingNumber FROM Win32_ComputerSystemProduct", L"IdentifyingNumber" },
    { FieldKey::kSysFamily,       L"SELECT SystemFamily FROM Win32_ComputerSystem", L"SystemFamily" },
    // 主板
    { FieldKey::kBoardManufacturer, L"SELECT Manufacturer FROM Win32_BaseBoard", L"Manufacturer" },
    { FieldKey::kBoardProduct,      L"SELECT Product FROM Win32_BaseBoard", L"Product" },
    { FieldKey::kBoardVersion,      L"SELECT Version FROM Win32_BaseBoard", L"Version" },
    { FieldKey::kBoardSerial,       L"SELECT SerialNumber FROM Win32_BaseBoard", L"SerialNumber" },
    // BIOS
    { FieldKey::kBiosVendor,      L"SELECT Manufacturer FROM Win32_BIOS", L"Manufacturer" },
    { FieldKey::kBiosVersion,     L"SELECT SMBIOSBIOSVersion FROM Win32_BIOS", L"SMBIOSBIOSVersion" },
    { FieldKey::kBiosSerial,      L"SELECT SerialNumber FROM Win32_BIOS", L"SerialNumber" },
    { FieldKey::kBiosReleaseDate, L"SELECT ReleaseDate FROM Win32_BIOS", L"ReleaseDate",
      &wmi_util::DatetimeToIsoDate },
    // CPU
    { FieldKey::kCpuManufacturer, L"SELECT Manufacturer FROM Win32_Processor", L"Manufacturer", nullptr, true },
    { FieldKey::kCpuName,         L"SELECT Name FROM Win32_Processor", L"Name", nullptr, true },
    { FieldKey::kCpuId,           L"SELECT ProcessorId FROM Win32_Processor", L"ProcessorId", nullptr, true },
    { FieldKey::kCpuCores,        L"SELECT NumberOfCores FROM Win32_Processor", L"NumberOfCores", nullptr, true },
    { FieldKey::kCpuThreads,      L"SELECT NumberOfLogicalProcessors FROM Win32_Processor", L"NumberOfLogicalProcessors", nullptr, true },
    // 内存（Capacity 统一为 MB，与 smbios 口径一致）
    { FieldKey::kMemorySize,    L"SELECT Capacity FROM Win32_PhysicalMemory", L"Capacity",
      &wmi_util::CapacityBytesToMb, true, "单位 MB" },
    { FieldKey::kMemorySerial,  L"SELECT SerialNumber FROM Win32_PhysicalMemory", L"SerialNumber", nullptr, true },
    { FieldKey::kMemoryPart,    L"SELECT PartNumber FROM Win32_PhysicalMemory", L"PartNumber", nullptr, true },
    { FieldKey::kMemoryLocator, L"SELECT DeviceLocator FROM Win32_PhysicalMemory", L"DeviceLocator", nullptr, true },
    // 磁盘（key_prop=Index：物理盘位号，供 ConsensusAligned 逐盘跨通道对齐；
    // 真机证据：WMI 返回顺序非升序（1,0,2），必须按盘位键排序）
    { FieldKey::kDiskModel,    L"SELECT Index, Model FROM Win32_DiskDrive", L"Model",
      nullptr, true, "", RowFilter::None, L"Index" },
    { FieldKey::kDiskSerial,   L"SELECT Index, SerialNumber FROM Win32_DiskDrive", L"SerialNumber",
      nullptr, true, "NVMe 序列号含下划线为原始格式（R4）", RowFilter::None, L"Index" },
    { FieldKey::kDiskFirmware, L"SELECT Index, FirmwareRevision FROM Win32_DiskDrive", L"FirmwareRevision",
      nullptr, true, "", RowFilter::None, L"Index" },
    { FieldKey::kDiskSizeBytes, L"SELECT Index, Size FROM Win32_DiskDrive", L"Size",
      nullptr, true, "字节", RowFilter::None, L"Index" },
    // 网卡（MAC 统一无分隔符，供 CONSENSUS 与 native 比较；R6：PNP 级过滤虚拟网卡，
    // 两条规格共用同一 WQL → 类缓存共享，仅 emitted 行计数；
    // key_prop=MACAddress：实例对齐键，ConsensusAligned 按 NIC 跨通道配对）
    { FieldKey::kNicMac,  L"SELECT Name, MACAddress, PNPDeviceID FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE",
      L"MACAddress", &wmi_util::MacNormalize, true, "", RowFilter::NicPnp, L"MACAddress" },
    { FieldKey::kNicName, L"SELECT Name, MACAddress, PNPDeviceID FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE",
      L"Name", nullptr, true, "", RowFilter::NicPnp, L"MACAddress" },
    // 显卡（gpu.name/vendor 只采集；gpu.uuid 由 native 通道供数并参与指纹——
    // R6：PCI 总线白名单 + 名称黑名单过滤虚拟显示适配器——
    // 真机证据：GameViewer 虚拟显示适配器 PNP 为 ROOT\DISPLAY，真显卡均为 PCI\VEN_*）
    { FieldKey::kGpuName,   L"SELECT Name, AdapterCompatibility, PNPDeviceID FROM Win32_VideoController", L"Name",
      nullptr, true, "", RowFilter::GpuVirtual },
    { FieldKey::kGpuVendor, L"SELECT Name, AdapterCompatibility, PNPDeviceID FROM Win32_VideoController", L"AdapterCompatibility",
      nullptr, true, "", RowFilter::GpuVirtual },
    // 机箱
    { FieldKey::kChassisManufacturer, L"SELECT Manufacturer FROM Win32_SystemEnclosure", L"Manufacturer" },
    { FieldKey::kChassisSerial,       L"SELECT SerialNumber FROM Win32_SystemEnclosure", L"SerialNumber" },
    // TPM（独立命名空间）
    { FieldKey::kTpmSpecVersion, L"SELECT SpecVersion FROM Win32_Tpm", L"SpecVersion" },
};

const WmiSpec* FindSpec(FieldKey key) {
    for (const auto& s : kSpecs)
        if (s.key == key) return &s;
    return nullptr;
}

std::string VariantToString(VARIANT& v) {
    switch (v.vt) {
    case VT_NULL:
    case VT_EMPTY: return {};
    case VT_BSTR:  return v.bstrVal ? textutil::Trim(textutil::WstrToUtf8(v.bstrVal))
                                    : std::string{};   // 缺失串属性可能给 null BSTR
    case VT_I4:    return std::to_string(v.lVal);
    case VT_UI4:   return std::to_string(v.ulVal);
    case VT_I8:    return std::to_string(v.llVal);
    case VT_UI8:   return std::to_string(v.ullVal);
    case VT_BOOL:  return v.boolVal ? "true" : "false";
    default:
        if (SUCCEEDED(VariantChangeType(&v, &v, 0, VT_BSTR)))
            return textutil::Trim(textutil::WstrToUtf8(v.bstrVal));
        return "<vt=" + std::to_string(v.vt) + ">";
    }
}

FieldResult Res(FieldKey key, int index, const std::string& v, const std::string& note = "") {
    FieldResult r;
    r.key   = key;
    r.index = index;
    r.value = v;
    r.note  = note;
    r.ok    = !v.empty();
    return r;
}

} // namespace

WmiChannel::~WmiChannel() {
    if (svc_)     ((IWbemServices*)svc_)->Release();
    if (tpm_svc_) ((IWbemServices*)tpm_svc_)->Release();
    if (locator_) ((IWbemLocator*)locator_)->Release();
}

void WmiChannel::SetOption(const char* key, int value) {
    if (key && std::string(key) == "tpm_probe") tpm_probe_ = (value != 0);
}

bool WmiChannel::Available() {
    if (!EnsureConnected()) return false;
    WarmCache();
    return true;
}

void WmiChannel::WarmCache() {
    for (const auto& spec : kSpecs) {
        // TPM 命名空间缺失时 Collect 已有降级路径，这里跳过预热
        if (spec.key == FieldKey::kTpmSpecVersion && !tpm_svc_) continue;
        IWbemServices* svc = (spec.key == FieldKey::kTpmSpecVersion)
                                 ? (IWbemServices*)tpm_svc_ : (IWbemServices*)svc_;
        EnsureClass(spec.wql, svc);
    }
}

bool WmiChannel::EnsureConnected() {
    std::lock_guard<std::mutex> lk(mu_);   // 连接建立与安全设置一次完成（happens-before）
    if (connected_) return true;

    if (!init_done_) {
        init_done_ = true;
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (hr == RPC_E_CHANGED_MODE) hr = S_FALSE;   // 已以 STA 初始化，仍可继续
        if (FAILED(hr)) { last_error_ = "CoInitializeEx failed"; return false; }
        // 已被其他组件初始化(RPC_E_TOO_LATE)不影响使用
        CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                             RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    }

    if (!locator_) {
        HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_IWbemLocator, &locator_);
        if (FAILED(hr)) { last_error_ = "CoCreateInstance(CLSID_WbemLocator) failed"; return false; }
    }
    IWbemLocator* loc = (IWbemLocator*)locator_;

    if (!svc_) {
        IWbemServices* svc = nullptr;
        HRESULT hr = loc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr,
                                        0, nullptr, nullptr, &svc);
        if (FAILED(hr)) {
            last_error_ = "ConnectServer(ROOT\\CIMV2) failed (WMI disabled or broken)";
            return false;
        }
        CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                          nullptr, EOAC_NONE);
        svc_ = svc;
    }

    // TPM 命名空间：默认不连接——部分主板（TPM 存在但未配置）该 ConnectServer
    // 固定阻塞 ~5s（本机实测 5016ms），拖垮整体耗时目标；tpm_probe=true 才探测
    if (tpm_probe_ && !tpm_svc_) {
        IWbemServices* tpm = nullptr;
        if (SUCCEEDED(loc->ConnectServer(_bstr_t(L"ROOT\\CIMV2\\Security\\MicrosoftTpm"),
                                         nullptr, nullptr, nullptr, 0, nullptr, nullptr, &tpm))) {
            CoSetProxyBlanket(tpm, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                              RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE);
            tpm_svc_ = tpm;
        }
    }

    connected_ = true;
    return true;
}

std::vector<FieldResult> WmiChannel::Fail(FieldKey key) const {
    return { Res(key, 0, "", "wmi unavailable: " + last_error_) };
}

// 确保一条 WQL 已查询并缓存（同类互斥，异类并发；std::map 引用稳定）
const WmiChannel::ClassCache& WmiChannel::EnsureClass(const std::wstring& wql, void* svc) {
    ClassCache* entry = nullptr;
    {
        std::lock_guard<std::mutex> lk(cache_map_mu_);
        entry = &class_cache_[wql];
    }
    std::lock_guard<std::mutex> lk(entry->mu);
    if (entry->done) return *entry;

    IWbemServices* svc_i = (IWbemServices*)svc;
    IEnumWbemClassObject* en = nullptr;
    HRESULT hr = svc_i->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wql.c_str()),
                                  WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                  nullptr, &en);
    if (FAILED(hr)) {
        char b[16];
        std::snprintf(b, sizeof b, "0x%08lX", (unsigned long)hr);
        entry->error = std::string("ExecQuery failed hr=") + b;
        entry->done = true;
        return *entry;
    }

    ULONG got = 0;
    IWbemClassObject* obj = nullptr;
    while (en->Next(WBEM_INFINITE, 1, &obj, &got) == S_OK) {
        // 整行属性枚举：类查询一次，任意属性字段共享
        std::map<std::string, std::string> row;
        if (SUCCEEDED(obj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY))) {
            BSTR name = nullptr;
            VARIANT pv;
            VariantInit(&pv);
            while (obj->Next(0, &name, &pv, nullptr, nullptr) == S_OK) {
                row[textutil::WstrToUtf8(name)] = VariantToString(pv);
                VariantClear(&pv);
                SysFreeString(name);
                name = nullptr;
            }
            obj->EndEnumeration();
        }
        entry->rows.push_back(std::move(row));
        obj->Release();
    }
    en->Release();
    entry->ok = true;
    entry->done = true;
    return *entry;
}

std::vector<FieldResult> WmiChannel::Collect(FieldKey key) {
    if (!EnsureConnected()) return Fail(key);
    const WmiSpec* spec = FindSpec(key);
    if (!spec) return {};   // 非本通道字段

    // TPM 字段走独立命名空间；不可达即该字段降级
    IWbemServices* svc = (IWbemServices*)svc_;
    if (key == FieldKey::kTpmSpecVersion) {
        if (!tpm_probe_)
            return { Res(key, 0, "",
                         "未启用 tpm_probe（连接该命名空间在部分主板阻塞数秒）") };
        if (!tpm_svc_)
            return { Res(key, 0, "", "MicrosoftTpm 命名空间不可达（无 TPM 或被策略禁用）") };
        svc = (IWbemServices*)tpm_svc_;
    }

    const ClassCache& cc = EnsureClass(spec->wql, svc);
    if (!cc.ok) return { Res(key, 0, "", cc.error) };

    const std::string prop = textutil::WstrToUtf8(spec->property);
    const std::string key_prop = spec->key_prop ? textutil::WstrToUtf8(spec->key_prop)
                                                : std::string();
    std::vector<FieldResult> out;
    int idx = 0;
    for (const auto& row : cc.rows) {
        // R6：虚拟设备行过滤（网卡 PNP 总线白名单 / 显卡总线+名称）
        if (spec->filter == RowFilter::NicPnp) {
            auto pid = row.find("PNPDeviceID");
            if (pid == row.end() || !wmi_util::NicPnpLikelyPhysical(pid->second)) continue;
        } else if (spec->filter == RowFilter::GpuVirtual) {
            auto pid = row.find("PNPDeviceID");
            if (pid == row.end() || !wmi_util::GpuPnpLikelyPhysical(pid->second)) continue;
            auto nm = row.find("Name");
            if (nm != row.end() && wmi_util::GpuNameLooksVirtual(nm->second)) continue;
        }
        auto it = row.find(prop);
        std::string val = it != row.end() ? it->second : std::string();
        if (spec->transform) val = spec->transform(val);
        std::string note = spec->note;
        if (val.empty() && note.empty()) note = "属性缺失或为空";
        std::string ikey;
        if (!key_prop.empty()) {
            auto kit = row.find(key_prop);
            if (kit != row.end()) ikey = kit->second;
        }
        FieldResult r = Res(key, spec->indexed ? idx : 0, val, note);
        r.instance_key = ikey;   // 盘位对齐键（ConsensusAligned 用）
        out.push_back(std::move(r));
        ++idx;
    }
    if (out.empty())   // 类查询成功但零实例（如无内存条），仍输出一条 ok=false 保持字段存在
        out.push_back(Res(key, 0, "", "类查询零实例"));
    return out;
}

std::vector<FieldKey> WmiChannel::SupportedFields() const {
    std::vector<FieldKey> keys;
    for (const auto& s : kSpecs) keys.push_back(s.key);
    return keys;
}

namespace wmi_channel_test {
int NicFilterSpecCountForTest() {
    int n = 0;
    for (const auto& s : kSpecs)
        if (s.filter == RowFilter::NicPnp) ++n;
    return n;
}
int GpuFilterSpecCountForTest() {
    int n = 0;
    for (const auto& s : kSpecs)
        if (s.filter == RowFilter::GpuVirtual) ++n;
    return n;
}
int KeyedSpecCountForTest() {
    int n = 0;
    for (const auto& s : kSpecs)
        if (s.key_prop) ++n;
    return n;
}
} // namespace wmi_channel_test

REGISTER_CHANNEL(WmiChannel)
