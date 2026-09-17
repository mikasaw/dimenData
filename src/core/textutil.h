// ============================================================
// 文本工具（零依赖内联）
// ============================================================
#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>

namespace textutil {

// UTF-16 → UTF-8（WMI/Win32 宽串输出统一走这里）
inline std::string WstrToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

inline std::string Hex(const unsigned char* b, size_t n) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[b[i] >> 4]; s += d[b[i] & 0xF]; }
    return s;
}

inline std::string ToLower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

inline std::string Trim(const std::string& s) {
    const char* ws = " \t\r\n";
    size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
}

} // namespace textutil
