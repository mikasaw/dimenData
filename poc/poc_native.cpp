// ============================================================
// M1 POC —— Native 通道（CPUID / IP Helper / CNG / 存储端口驱动 / TBS）
// ============================================================
// winsock2.h 必须先于 windows.h：iptypes.h 的 GAA 段（IP_ADAPTER_ADDRESSES、
// GAA_FLAG_*）包在 #ifdef _WINSOCK2API_ 内，需先引入 winsock2 才会生效
#include <winsock2.h>
#include "poc_common.h"
#include <intrin.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <tbs.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "bcrypt")
#pragma comment(lib, "tbs")

namespace {

std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)tolower(c); });
    return s;
}

void CpuIdPoc() {
    int r[4] = {};
    __cpuid(r, 0);
    char vend[13] = {};
    std::memcpy(vend, &r[1], 4);
    std::memcpy(vend + 4, &r[3], 4);
    std::memcpy(vend + 8, &r[2], 4);
    PocReport({"native", "cpu.vendor_id", vend, "CPUID leaf 0"});

    __cpuid(r, 0x80000000);
    if ((unsigned)r[0] >= 0x80000004) {
        char brand[49] = {};
        for (int i = 0; i < 3; ++i) {
            int b[4];
            __cpuid(b, 0x80000002 + i);
            std::memcpy(brand + i * 16, b, 16);
        }
        PocReport({"native", "cpu.brand", Trim(brand), "CPUID 0x80000002-4"});
    }
}

void AdaptersPoc() {
    ULONG sz = 16 * 1024;
    std::vector<BYTE> buf(sz);
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG err = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                     (IP_ADAPTER_ADDRESSES*)buf.data(), &sz);
    if (err == ERROR_BUFFER_OVERFLOW) {
        buf.resize(sz);
        err = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                   (IP_ADAPTER_ADDRESSES*)buf.data(), &sz);
    }
    if (err != NO_ERROR) {
        PocReport({"native", "nic[0].mac", "", "GetAdaptersAddresses 失败"});
        return;
    }
    int i = 0;
    for (auto* a = (IP_ADAPTER_ADDRESSES*)buf.data(); a; a = a->Next, ++i) {
        const std::string name = WstrToUtf8(a->FriendlyName);
        const std::string desc = WstrToUtf8(a->Description);
        std::string note = name + " | " + desc;
        const bool skip = (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) ||
                          (a->IfType == IF_TYPE_TUNNEL) ||
                          (a->PhysicalAddressLength == 0);
        std::string mac;
        if (skip) {
            note += " | 回环/隧道/无MAC，跳过";
        } else {
            mac = Hex(a->PhysicalAddress, a->PhysicalAddressLength);
            const std::string d = Lower(desc);
            static const char* kVirtual[] = { "virtual", "vmware", "hyper-v", "vethernet",
                                              "tap", "loopback", "wan miniport",
                                              "bluetooth", "vpn", "teredo", "vbox" };
            for (const char* v : kVirtual)
                if (d.find(v) != std::string::npos) { note += " | 疑似虚拟/非物理"; break; }
        }
        PocReport({"native", "nic[" + std::to_string(i) + "].mac", skip ? "" : mac, note});
    }
}

void CngHashPoc() {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
        PocReport({"native", "crypto.sha256", "", "BCryptOpenAlgorithmProvider 失败"});
        return;
    }
    BCRYPT_HASH_HANDLE h = nullptr;
    BYTE out[32] = {};
    const char* msg    = "abc";
    // 参考值大写，与 Hex() 输出一致（此前用小写导致误报“不符”）
    const char* expect = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
    if (BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0)) &&
        BCRYPT_SUCCESS(BCryptHashData(h, (PUCHAR)msg, 3, 0)) &&
        BCRYPT_SUCCESS(BCryptFinishHash(h, out, sizeof(out), 0))) {
        const std::string got = Hex(out, sizeof(out));
        PocReport({"native", "crypto.sha256", got == expect ? "pass" : got,
                   got == expect ? "与参考值一致" : "与参考值不符"});
    } else {
        PocReport({"native", "crypto.sha256", "", "CNG 哈希失败"});
    }
    if (h) BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
}

void DiskPoc() {
    // 访问权限传 0：仅查询属性，普通用户即可，不做任何读写
    HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        PocReport({"native", "disk.serial", "",
                   "打开 PhysicalDrive0 失败 GetLastError=" + std::to_string(GetLastError())});
        return;
    }
    STORAGE_PROPERTY_QUERY q = {};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType  = PropertyStandardQuery;
    BYTE out[4096] = {};
    DWORD br = 0;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q),
                        out, sizeof(out), &br, nullptr) &&
        br >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        auto* d    = (STORAGE_DEVICE_DESCRIPTOR*)out;
        auto  pick = [&](DWORD off) -> std::string {
            if (!off || off >= br) return {};
            return Trim(std::string((const char*)out + off,
                                    strnlen((const char*)out + off, br - off)));
        };
        PocReport({"native", "disk.vendor",   pick(d->VendorIdOffset), "IOCTL_STORAGE_QUERY_PROPERTY"});
        PocReport({"native", "disk.product",  pick(d->ProductIdOffset), ""});
        PocReport({"native", "disk.firmware", pick(d->ProductRevisionOffset), ""});
        PocReport({"native", "disk.serial",   pick(d->SerialNumberOffset),
                   d->SerialNumberOffset ? "" : "该 IOCTL 未返回序列号（NVMe 需专用查询，M2 处理）"});
    } else {
        PocReport({"native", "disk.serial", "", "IOCTL_STORAGE_QUERY_PROPERTY 失败"});
    }
    CloseHandle(h);
}

void TpmPoc() {
    TBS_HCONTEXT ctx = 0;
    TBS_CONTEXT_PARAMS params = {};
    params.version = 1;  // TBS_CONTEXT_VERSION_ONE（头文件未定义宏，按文档取值）
    const TBS_RESULT r = Tbsi_Context_Create(&params, &ctx);
    if (r == TBS_SUCCESS) {
        PocReport({"native", "tpm.available", "yes", "TBS 上下文创建成功"});
        Tbsip_Context_Close(ctx);
    } else {
        char b[16];
        snprintf(b, sizeof b, "0x%X", (unsigned)r);
        std::string note = "Tbsip_Context_Create 失败 code=" + std::string(b);
        if (r == (TBS_RESULT)TBS_E_TPM_NOT_FOUND) note += "（未找到 TPM 或未启用）";
        PocReport({"native", "tpm.available", "", note});
    }
}

} // namespace

void PocNative() {
    CpuIdPoc();
    AdaptersPoc();
    CngHashPoc();
    DiskPoc();
    TpmPoc();
}
