// ============================================================
// M1 POC —— WMI 通道（COM / IWbemLocator，ROOT\CIMV2）
// 验证矩阵：sys.* / board.* / bios.* / cpu.* / memory[*] / disk[*] /
//           gpu[*] / nic[*] / chassis.* / tpm.*
// ============================================================
#define _WIN32_DCOM
#include "poc_common.h"
#include <comdef.h>
#include <Wbemidl.h>
#include <cstdio>
#include <initializer_list>
#include <utility>

#pragma comment(lib, "wbemuuid")

namespace {

std::string VariantToStr(VARIANT& v) {
    switch (v.vt) {
    case VT_NULL:
    case VT_EMPTY: return {};
    case VT_BSTR:  return Trim(WstrToUtf8(v.bstrVal));
    case VT_I4:    return std::to_string(v.lVal);
    case VT_UI4:   return std::to_string(v.ulVal);
    case VT_I8:    return std::to_string(v.llVal);
    case VT_UI8:   return std::to_string(v.ullVal);
    case VT_BOOL:  return v.boolVal ? "true" : "false";
    default: {
        if (SUCCEEDED(VariantChangeType(&v, &v, 0, VT_BSTR)))
            return Trim(WstrToUtf8(v.bstrVal));
        return "<vt=" + std::to_string(v.vt) + ">";
    }
    }
}

using Prop = std::pair<std::string, std::string>;  // (字段键, WMI 属性名——属性名均为 ASCII)

void DumpQuery(IWbemServices* svc, const wchar_t* wql,
               std::initializer_list<Prop> props, bool indexed = false) {
    IEnumWbemClassObject* en = nullptr;
    HRESULT hr = svc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wql),
                                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                nullptr, &en);
    if (FAILED(hr)) {
        char b[16];
        snprintf(b, sizeof b, "0x%08lX", (unsigned long)hr);
        PocReport({"wmi", "query.error", "", std::string("hr=") + b + "  " + WstrToUtf8(wql)});
        return;
    }
    int idx = 0;
    ULONG got = 0;
    IWbemClassObject* obj = nullptr;
    while (en->Next(WBEM_INFINITE, 1, &obj, &got) == S_OK) {
        for (const Prop& p : props) {
            std::string key = p.first;
            if (indexed) key += "[" + std::to_string(idx) + "]";
            VARIANT v;
            VariantInit(&v);
            std::string val, note;
            const std::wstring wprop(p.second.begin(), p.second.end());  // ASCII 属性名直接拓宽
            if (SUCCEEDED(obj->Get(wprop.c_str(), 0, &v, nullptr, nullptr)))
                val = VariantToStr(v);
            else
                note = "Get 失败";
            VariantClear(&v);
            PocReport({"wmi", key, val, note});
        }
        obj->Release();
        ++idx;
    }
    en->Release();
    if (idx == 0)
        PocReport({"wmi", "query.empty", "", WstrToUtf8(wql)});
}

} // namespace

void PocWmi() {
    HRESULT hrCo = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (hrCo == RPC_E_CHANGED_MODE) hrCo = S_FALSE;  // 已以 STA 初始化，仍可继续
    if (FAILED(hrCo)) {
        PocReport({"wmi", "channel.available", "", "CoInitializeEx 失败"});
        return;
    }
    // 已被其他组件初始化(RPC_E_TOO_LATE)不影响使用
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

    IWbemLocator* loc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (void**)&loc);
    if (FAILED(hr)) {
        PocReport({"wmi", "channel.available", "", "CoCreateInstance(CLSID_WbemLocator) 失败"});
        return;
    }
    IWbemServices* svc = nullptr;
    hr = loc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr,
                            0, nullptr, nullptr, &svc);
    if (FAILED(hr)) {
        PocReport({"wmi", "channel.available", "", "ConnectServer(ROOT\\CIMV2) 失败（WMI 服务被禁用/损坏）"});
        loc->Release();
        return;
    }
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      nullptr, EOAC_NONE);
    PocReport({"wmi", "channel.available", "yes", "ROOT\\CIMV2 连接成功"});

    DumpQuery(svc, L"SELECT Manufacturer, Model, SystemFamily FROM Win32_ComputerSystem",
              {{"sys.manufacturer", "Manufacturer"}, {"sys.model", "Model"},
               {"sys.family", "SystemFamily"}});
    DumpQuery(svc, L"SELECT IdentifyingNumber, Name, Vendor, Version FROM Win32_ComputerSystemProduct",
              {{"sys.serial", "IdentifyingNumber"}, {"sys.product", "Name"},
               {"sys.manufacturer", "Vendor"}, {"sys.version", "Version"}});
    DumpQuery(svc, L"SELECT Manufacturer, Product, Version, SerialNumber FROM Win32_BaseBoard",
              {{"board.manufacturer", "Manufacturer"}, {"board.product", "Product"},
               {"board.version", "Version"}, {"board.serial", "SerialNumber"}});
    DumpQuery(svc, L"SELECT Manufacturer, Name, SMBIOSBIOSVersion, SerialNumber, ReleaseDate FROM Win32_BIOS",
              {{"bios.vendor", "Manufacturer"}, {"bios.name", "Name"},
               {"bios.version", "SMBIOSBIOSVersion"}, {"bios.serial", "SerialNumber"},
               {"bios.release_date", "ReleaseDate"}});
    DumpQuery(svc, L"SELECT Manufacturer, Name, ProcessorId, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor",
              {{"cpu.manufacturer", "Manufacturer"}, {"cpu.name", "Name"},
               {"cpu.processor_id", "ProcessorId"}, {"cpu.cores", "NumberOfCores"},
               {"cpu.threads", "NumberOfLogicalProcessors"}, {"cpu.max_clock_mhz", "MaxClockSpeed"}}, true);
    DumpQuery(svc, L"SELECT DeviceLocator, Manufacturer, SerialNumber, PartNumber, Capacity, Speed FROM Win32_PhysicalMemory",
              {{"memory.locator", "DeviceLocator"}, {"memory.manufacturer", "Manufacturer"},
               {"memory.serial", "SerialNumber"}, {"memory.part", "PartNumber"},
               {"memory.bytes", "Capacity"}, {"memory.speed_mhz", "Speed"}}, true);
    DumpQuery(svc, L"SELECT Index, Model, SerialNumber, FirmwareRevision, InterfaceType, MediaType, Size FROM Win32_DiskDrive",
              {{"disk.index", "Index"}, {"disk.model", "Model"}, {"disk.serial", "SerialNumber"},
               {"disk.firmware", "FirmwareRevision"}, {"disk.interface", "InterfaceType"},
               {"disk.mediatype", "MediaType"}, {"disk.bytes", "Size"}}, true);
    DumpQuery(svc, L"SELECT Name, AdapterCompatibility, DriverVersion, VideoProcessor FROM Win32_VideoController",
              {{"gpu.name", "Name"}, {"gpu.vendor", "AdapterCompatibility"},
               {"gpu.driver", "DriverVersion"}, {"gpu.chip", "VideoProcessor"}}, true);
    DumpQuery(svc, L"SELECT Name, MACAddress, NetConnectionID, Speed FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE",
              {{"nic.name", "Name"}, {"nic.mac", "MACAddress"},
               {"nic.conn", "NetConnectionID"}, {"nic.speed_bps", "Speed"}}, true);
    DumpQuery(svc, L"SELECT Manufacturer, SerialNumber FROM Win32_SystemEnclosure",
              {{"chassis.manufacturer", "Manufacturer"}, {"chassis.serial", "SerialNumber"}});

    // TPM 独立命名空间
    IWbemServices* tpm = nullptr;
    if (SUCCEEDED(loc->ConnectServer(_bstr_t(L"ROOT\\CIMV2\\Security\\MicrosoftTpm"),
                                     nullptr, nullptr, nullptr, 0, nullptr, nullptr, &tpm))) {
        CoSetProxyBlanket(tpm, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                          nullptr, EOAC_NONE);
        DumpQuery(tpm, L"SELECT SpecVersion, ManufacturerIdTxt, IsEnabled_InitialValue, IsActivated_InitialValue FROM Win32_Tpm",
                  {{"tpm.specversion", "SpecVersion"}, {"tpm.manufacturer", "ManufacturerIdTxt"},
                   {"tpm.enabled", "IsEnabled_InitialValue"}, {"tpm.activated", "IsActivated_InitialValue"}});
        tpm->Release();
    } else {
        PocReport({"wmi", "tpm.specversion", "", "MicrosoftTpm 命名空间不可达（无 TPM 或被策略禁用）"});
    }

    svc->Release();
    loc->Release();
}
