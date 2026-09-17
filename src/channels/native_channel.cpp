#include <winsock2.h>
#include <windows.h>
#include "channels/native_channel.h"
#include "core/channel_registry.h"   // REGISTER_CHANNEL 宏
#include "core/textutil.h"
#include <iphlpapi.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <tbs.h>
#include <shlobj.h>     // SHGetKnownFolderPath（nvidia-smi 路径取权威系统位置）
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "bcrypt")
#pragma comment(lib, "tbs")
#pragma comment(lib, "shell32")
#pragma comment(lib, "ole32")   // CoTaskMemFree

namespace {

FieldResult Res(FieldKey key, int index, const std::string& v, const std::string& note = "",
                const std::string& instance_key = "") {
    FieldResult r;
    r.key   = key;
    r.index = index;
    r.value = v;
    r.note  = note;
    r.ok    = !v.empty();
    r.instance_key = instance_key;
    return r;
}

std::vector<NativeDisk> ProbeDisks() {
    std::vector<NativeDisk> out;
    for (int idx = 0; idx < 8; ++idx) {
        wchar_t path[32];
        std::swprintf(path, 32, L"\\\\.\\PhysicalDrive%d", idx);
        // 访问权限 0：仅查询属性，普通用户即可，不做任何读写
        HANDLE h = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;  // 盘号可稀疏（热拔/禁用不回缩），失败继续下一盘
        STORAGE_PROPERTY_QUERY q = {};
        q.PropertyId = StorageDeviceProperty;
        q.QueryType  = PropertyStandardQuery;
        BYTE out_buf[4096] = {};
        DWORD br = 0;
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q),
                            out_buf, sizeof(out_buf), &br, nullptr) &&
            br >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            auto* d = (STORAGE_DEVICE_DESCRIPTOR*)out_buf;
            auto pick = [&](DWORD off) -> std::string {
                if (!off || off >= br) return {};
                return textutil::Trim(
                    std::string((const char*)out_buf + off,
                                strnlen((const char*)out_buf + off, br - off)));
            };
            NativeDisk nd;
            nd.number = idx;   // 盘位号 = PhysicalDriveN（与 WMI Index 同源）
            const std::string vendor = pick(d->VendorIdOffset);
            const std::string product = pick(d->ProductIdOffset);
            nd.model    = vendor.empty() ? product : vendor + " " + product;
            nd.serial   = pick(d->SerialNumberOffset);
            nd.firmware = pick(d->ProductRevisionOffset);
            out.push_back(std::move(nd));
        }
        CloseHandle(h);
    }
    return out;
}

// 定位 nvidia-smi（System32 优先，兼容旧版 NVSMI 目录）；找不到返回空。
// 路径取系统 API（GetWindowsDirectoryW / SHGetKnownFolderPath）而非环境变量，
// 避免被篡改的 %ProgramFiles% 指向任意可执行文件。
std::wstring LocateNvidiaSmi() {
    wchar_t win[MAX_PATH];
    if (GetWindowsDirectoryW(win, MAX_PATH)) {
        const std::wstring p = std::wstring(win) + L"\\System32\\nvidia-smi.exe";
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return p;
    }
    PWSTR pf = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &pf)) && pf) {
        const std::wstring p = std::wstring(pf) +
                               L"\\NVIDIA Corporation\\NVSMI\\nvidia-smi.exe";
        CoTaskMemFree(pf);
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return p;
    } else if (pf) {
        CoTaskMemFree(pf);
    }
    return {};
}

// 执行外部命令并捕获 stdout（临时文件承接 + 硬超时 + 句柄白名单继承）。
// 用临时文件而非管道：管道读与等待存在死锁风险，临时文件可先 Wait 超时再读。
// 输出极小（几百字节），无性能顾虑；文件用后即删。
// 注意：本函数会以 CREATE_NO_WINDOW 拉起第三方进程（nvidia-smi），
// 属杀软/EDR 关注的进程创建行为——调用方须保持参数固定、路径来自系统 API。
bool RunCaptureToFile(const std::wstring& exe, const std::wstring& args,
                      DWORD timeout_ms, std::string& out) {
    wchar_t tempDir[MAX_PATH], tempFile[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempDir)) return false;
    if (!GetTempFileNameW(tempDir, L"hwu", 0, tempFile)) return false;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hOut = CreateFileW(tempFile, GENERIC_WRITE, FILE_SHARE_READ, &sa,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    HANDLE hNul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &sa,
                              OPEN_EXISTING, 0, nullptr);
    bool ok = false;
    if (hOut != INVALID_HANDLE_VALUE && hNul != INVALID_HANDLE_VALUE) {
        STARTUPINFOEXW six{};
        six.StartupInfo.cb = sizeof(six);
        six.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        six.StartupInfo.hStdInput  = hNul;
        six.StartupInfo.hStdOutput = hOut;
        six.StartupInfo.hStdError  = hOut;   // stderr 一并捕获，便于诊断且避免弹窗

        // 句柄白名单：即使 bInheritHandles=TRUE，子进程也只继承列出的这两个句柄
        HANDLE inherit[2] = { hNul, hOut };
        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
        std::vector<BYTE> attrBuf(attrSize);
        PPROC_THREAD_ATTRIBUTE_LIST attrs = (PPROC_THREAD_ATTRIBUTE_LIST)attrBuf.data();
        const bool attrOk =
            InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize) &&
            UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                      inherit, sizeof(inherit), nullptr, nullptr);
        if (attrOk) six.lpAttributeList = attrs;

        PROCESS_INFORMATION pi{};
        std::wstring cmd = L"\"" + exe + L"\" " + args;
        std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
        cmdBuf.push_back(L'\0');
        const DWORD flags = CREATE_NO_WINDOW |
                            (attrOk ? EXTENDED_STARTUPINFO_PRESENT : 0);
        if (CreateProcessW(exe.c_str(), cmdBuf.data(), nullptr, nullptr, TRUE,
                           flags, nullptr, nullptr, &six.StartupInfo, &pi)) {
            CloseHandle(pi.hThread);
            const DWORD w = WaitForSingleObject(pi.hProcess, timeout_ms);
            if (w == WAIT_TIMEOUT) {
                TerminateProcess(pi.hProcess, 1);
                WaitForSingleObject(pi.hProcess, 1000);   // 收尸，避免僵尸
            }
            CloseHandle(pi.hProcess);
            ok = (w == WAIT_OBJECT_0);
        }
        if (attrOk) DeleteProcThreadAttributeList(attrs);
    }
    if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
    if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);

    if (ok) {
        HANDLE hIn = CreateFileW(tempFile, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
        if (hIn != INVALID_HANDLE_VALUE) {
            char buf[4096];
            DWORD rd = 0;
            while (ReadFile(hIn, buf, sizeof(buf), &rd, nullptr) && rd > 0)
                out.append(buf, rd);
            CloseHandle(hIn);
        }
    }
    DeleteFileW(tempFile);
    return ok;
}

int ProbeTbs() {
    TBS_HCONTEXT ctx = 0;
    TBS_CONTEXT_PARAMS params = {};
    params.version = 1;   // TBS_CONTEXT_VERSION_ONE（头文件未定义宏，按文档取值）
    const TBS_RESULT r = Tbsi_Context_Create(&params, &ctx);
    if (r == TBS_SUCCESS) Tbsip_Context_Close(ctx);
    return (int)r;
}

// CNG SHA-256 自检："abc" 的参考哈希
std::string CryptoSelfTest() {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return "bcrypt open failed";
    BCRYPT_HASH_HANDLE h = nullptr;
    BYTE out[32] = {};
    const char* msg    = "abc";
    const char* expect = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
    std::string result;
    if (BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0)) &&
        BCRYPT_SUCCESS(BCryptHashData(h, (PUCHAR)msg, 3, 0)) &&
        BCRYPT_SUCCESS(BCryptFinishHash(h, out, sizeof(out), 0))) {
        result = textutil::Hex(out, sizeof(out)) == std::string(expect) ? "pass"
                                                                       : "hash mismatch";
    } else {
        result = "hash api failed";
    }
    if (h) BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return result;
}

} // namespace

void NativeChannel::EnsureProbed() {
    std::lock_guard<std::mutex> lk(mu_);
    if (probed_) return;
    probed_ = true;

    int r0[4] = {};
    __cpuid(r0, 0);

    int hi[4] = {};
    __cpuid(hi, 0x80000000);
    if ((unsigned)hi[0] >= 0x80000004) {
        int leaves[3][4];
        for (int i = 0; i < 3; ++i) __cpuid(leaves[i], 0x80000002 + i);
        cpu_.brand = native_util::CpuBrandFromLeaves(leaves);
    }

    int l1[4] = {};
    __cpuid(l1, 1);
    cpu_.id_hex = native_util::CpuIdFromLeaf1(l1[0], l1[3]);

    disks_ = ProbeDisks();
    {
        const std::wstring smi = LocateNvidiaSmi();
        if (smi.empty()) {
            nvidia_note_ = "nvidia-smi 未找到（非 NVIDIA 平台或无 NVIDIA 驱动）";
        } else {
            std::string csv;
            if (!RunCaptureToFile(smi, L"--query-gpu=index,name,uuid --format=csv,noheader",
                                  3000, csv)) {
                nvidia_note_ = "nvidia-smi 执行失败或超时(3s)";
            } else {
                nvidia_gpus_ = native_util::ParseNvidiaSmiUuidCsv(csv);
                if (nvidia_gpus_.empty()) nvidia_note_ = "nvidia-smi 输出无有效 GPU UUID";
            }
        }
    }
    tbs_code_ = ProbeTbs();
    crypto_result_ = CryptoSelfTest();
}

std::vector<FieldKey> NativeChannel::SupportedFields() const {
    return {
        FieldKey::kCpuName, FieldKey::kCpuId,
        FieldKey::kNicMac, FieldKey::kNicName,
        FieldKey::kDiskModel, FieldKey::kDiskSerial, FieldKey::kDiskFirmware,
        FieldKey::kGpuUuid,
        FieldKey::kMetaCryptoSelfTest, FieldKey::kTpmAvailable,
    };
}

std::vector<FieldResult> NativeChannel::Collect(FieldKey key) {
    EnsureProbed();
    std::vector<FieldResult> out;
    switch (key) {
    case FieldKey::kCpuName:
        out.push_back(Res(key, 0, cpu_.brand, "CPUID 0x80000002-4"));
        break;
    case FieldKey::kCpuId:
        out.push_back(Res(key, 0, cpu_.id_hex,
                          "CPUID leaf1 EDX:EAX；低字节含 APIC ID（R2）"));
        break;

    case FieldKey::kNicMac:
    case FieldKey::kNicName: {
        ULONG sz = 16 * 1024;
        std::vector<uint8_t> buf(sz);
        const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                            GAA_FLAG_SKIP_DNS_SERVER;
        ULONG err = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                         (IP_ADAPTER_ADDRESSES*)buf.data(), &sz);
        if (err == ERROR_BUFFER_OVERFLOW) {
            buf.resize(sz);
            err = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                       (IP_ADAPTER_ADDRESSES*)buf.data(), &sz);
        }
        if (err != NO_ERROR) {
            out.push_back(Res(key, 0, "", "GetAdaptersAddresses failed"));
            break;
        }
        int i = 0;
        for (auto* a = (IP_ADAPTER_ADDRESSES*)buf.data(); a; a = a->Next) {
            const std::string desc = textutil::ToLower(textutil::WstrToUtf8(a->Description));
            if (!native_util::NicLikelyPhysical(a->IfType, desc)) continue;   // R6 初筛
            if (a->PhysicalAddressLength == 0) continue;
            // 实例对齐键 = 连续 hex MAC（wmi 冒号分隔形态经 NormalizeInstanceKey 归一）
            const std::string mac =
                textutil::Hex(a->PhysicalAddress, a->PhysicalAddressLength);
            if (key == FieldKey::kNicMac)
                out.push_back(Res(key, i, mac, "", mac));
            else
                out.push_back(Res(key, i, textutil::WstrToUtf8(a->FriendlyName), "", mac));
            ++i;
        }
        break;
    }

    case FieldKey::kDiskModel:
        for (size_t i = 0; i < disks_.size(); ++i)
            out.push_back(Res(key, (int)i, disks_[i].model, "IOCTL_STORAGE_QUERY_PROPERTY",
                              std::to_string(disks_[i].number)));
        break;
    case FieldKey::kDiskSerial:
        for (size_t i = 0; i < disks_.size(); ++i)
            out.push_back(Res(key, (int)i, disks_[i].serial,
                              disks_[i].serial.empty() ? "本接口未返回序列号" : "",
                              std::to_string(disks_[i].number)));
        break;
    case FieldKey::kDiskFirmware:
        for (size_t i = 0; i < disks_.size(); ++i)
            out.push_back(Res(key, (int)i, disks_[i].firmware, "",
                              std::to_string(disks_[i].number)));
        break;

    case FieldKey::kGpuUuid:
        // NVIDIA 平台卡级 UUID（消费级卡无序列号，UUID 为唯一稳定标识）；
        // 其他厂商/无驱动 → 单条 ok=false 降级并写明原因
        if (nvidia_gpus_.empty()) {
            out.push_back(Res(key, 0, "", nvidia_note_.empty() ? "无 NVIDIA GPU UUID" : nvidia_note_));
        } else {
            for (size_t i = 0; i < nvidia_gpus_.size(); ++i)
                out.push_back(Res(key, (int)i, nvidia_gpus_[i].uuid,
                                  nvidia_gpus_[i].name + "（nvidia 索引 " +
                                      nvidia_gpus_[i].index + "）",
                                  nvidia_gpus_[i].index));
        }
        break;
    case FieldKey::kMetaCryptoSelfTest:
        out.push_back(Res(key, 0, crypto_result_, "CNG SHA-256(\"abc\") 参考值比对"));
        break;
    case FieldKey::kTpmAvailable: {
        char b[16];
        std::snprintf(b, sizeof b, "0x%X", (unsigned)tbs_code_);
        out.push_back(tbs_code_ == 0
                          ? Res(key, 0, "yes", "TBS 上下文创建成功")
                          : Res(key, 0, "", std::string("TBS code=") + b));
        break;
    }
    default:
        break;
    }
    return out;
}

REGISTER_CHANNEL(NativeChannel)
