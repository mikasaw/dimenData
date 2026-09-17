// ============================================================
// dimenData M1 POC —— 多通道采集验证公共设施
// 每个采集通道实现一个 Poc<Channel>() 入口，统一通过 PocReport 上报，
// 对应正式版 FieldResult{ key, value, source, status } 的雏形。
// ============================================================
#pragma once
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>

struct PocField {
    std::string channel;   // 通道：smbios / wmi / registry / native
    std::string field;     // 字段键：与正式版 fields.def 命名一致，如 board.serial
    std::string value;     // 采集值；空串表示未取到
    std::string note;      // 备注：来源说明 / 失败原因 / 原始格式
};

inline std::vector<PocField>& PocResults() {
    static std::vector<PocField> v;
    return v;
}

inline void PocReport(const PocField& f) { PocResults().push_back(f); }

inline std::string WstrToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

inline std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

inline std::string Hex(const BYTE* b, size_t n) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[b[i] >> 4]; s += d[b[i] & 0xF]; }
    return s;
}

// 各通道入口（poc_main 调用）
void PocSmbios();
void PocWmi();
void PocRegistry();
void PocNative();
