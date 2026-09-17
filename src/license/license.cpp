#include "license/license.h"
#include "license/crypto.h"
#include "core/json.h"
#include <windows.h>
#include <cstdio>

namespace lic {

namespace {

const char* kCanonicalHeader = "HWFP-LICENSE-V1";

// canonical 以 '\n' 分行、';' 分隔键值对、'=' 连接——这些字符进入值域
// 会让 canonical 出现歧义行，签发与解析两侧均拒绝（防线双保险）
bool SafeLine(const std::string& s) {
    return s.find('\n') == std::string::npos && s.find('\r') == std::string::npos;
}

bool SafePart(const std::string& s) {
    if (s.empty()) return false;
    for (const char c : s)
        if (c == ';' || c == '=' || c == '\n' || c == '\r') return false;
    return true;
}

bool LooksHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (const char c : s) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

bool LooksIsoDate(const std::string& s) {
    if (s.size() != 10) return false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i == 4 || i == 7) { if (s[i] != '-') return false; }
        else if (s[i] < '0' || s[i] > '9') return false;
    }
    return true;
}

} // namespace

std::string BuildCanonical(const LicenseData& l) {
    std::string out = kCanonicalHeader;
    out += "\nlicensee=" + l.licensee;
    out += "\nissued_at=" + l.issued_at;
    out += "\nexpires_at=" + l.expires_at;
    out += "\nfingerprint=" + l.fingerprint;
    out += "\nsub=";
    bool first = true;
    for (const auto& kv : l.sub) {          // std::map → 组名升序
        if (!first) out += ';';
        first = false;
        out += kv.first + "=" + kv.second;
    }
    out += "\nfeatures=";
    first = true;
    for (const auto& kv : l.features) {     // 键升序
        if (!first) out += ';';
        first = false;
        out += kv.first + "=" + kv.second;
    }
    out += "\nnonce=" + l.nonce;
    return out;
}

bool ValidateFields(const LicenseData& l, std::string& err) {
    if (l.licensee.empty()) { err = "licensee 不能为空"; return false; }
    if (!SafeLine(l.licensee) || !SafeLine(l.issued_at) || !SafeLine(l.expires_at) ||
        !SafeLine(l.fingerprint) || !SafeLine(l.nonce)) {
        err = "授权字段含非法换行"; return false;
    }
    if (!LooksIsoDate(l.issued_at)) { err = "issued_at 须为 YYYY-MM-DD"; return false; }
    if (!l.expires_at.empty() && !LooksIsoDate(l.expires_at)) {
        err = "expires_at 须为 YYYY-MM-DD 或空"; return false;
    }
    if (!l.fingerprint.empty() && !LooksHex64(l.fingerprint)) {
        err = "fingerprint 须为 64 位十六进制或空"; return false;
    }
    for (const auto& kv : l.sub)
        if (!SafePart(kv.first) || !SafePart(kv.second)) {
            err = "sub 含非法分隔符（; =）或空值"; return false;
        }
    for (const auto& kv : l.features)
        if (!SafePart(kv.first) || !SafePart(kv.second)) {
            err = "features 含非法分隔符（; =）或空值"; return false;
        }
    if (l.nonce.empty()) { err = "nonce 不能为空"; return false; }
    return true;
}

bool ParseLicense(const std::string& json_text, LicenseData& l, std::string& err) {
    json::Value root;
    if (!json::Parse(json_text, root, err) || !root.IsObj() ||
        !root.obj.count("license") || !root.obj.at("license").IsObj()) {
        err = "授权文件格式无效（缺 license 对象）";
        return false;
    }
    const json::Value& o = root.obj.at("license");
    double schema = 0;
    if (!o.GetNum("schema", schema) || (int)schema != 1) {
        err = "license.schema 必须为 1";
        return false;
    }
    o.GetStr("licensee", l.licensee);
    o.GetStr("issued_at", l.issued_at);
    o.GetStr("expires_at", l.expires_at);
    o.GetStr("fingerprint", l.fingerprint);
    o.GetStr("nonce", l.nonce);
    o.GetStr("sig", l.sig);
    if (o.obj.count("sub") && o.obj.at("sub").IsObj())
        for (const auto& kv : o.obj.at("sub").obj)
            if (kv.second.IsStr()) l.sub[kv.first] = kv.second.str;
    if (o.obj.count("features") && o.obj.at("features").IsObj())
        for (const auto& kv : o.obj.at("features").obj)
            if (kv.second.IsStr()) l.features[kv.first] = kv.second.str;
    if (!ValidateFields(l, err)) return false;
    return true;
}

bool VerifySignature(const LicenseData& l, const std::string& pub_b64,
                     unsigned long* status) {
    return Verify(pub_b64, BuildCanonical(l), l.sig, status);
}

bool Issue(LicenseData& l, const std::string& priv_b64,
           std::string& json_out, std::string& err) {
    json_out.clear();
    if (!ValidateFields(l, err)) return false;
    std::string sig;
    if (!Sign(priv_b64, BuildCanonical(l), sig)) {
        err = "签名失败（私钥无效？）";
        return false;
    }
    l.sig = sig;
    std::string o = "{\n  \"license\": {\n";
    o += "    \"schema\": 1,\n";
    o += "    \"licensee\": \"" + json::Escape(l.licensee) + "\",\n";
    o += "    \"issued_at\": \"" + l.issued_at + "\",\n";
    o += "    \"expires_at\": \"" + l.expires_at + "\",\n";
    o += "    \"fingerprint\": \"" + l.fingerprint + "\",\n    \"sub\": {";
    bool first = true;
    for (const auto& kv : l.sub) {
        if (!first) o += ',';
        first = false;
        o += "\n      \"" + json::Escape(kv.first) + "\": \"" + kv.second + "\"";
    }
    o += (l.sub.empty() ? "},\n" : "\n    },\n");
    o += "    \"features\": {";
    first = true;
    for (const auto& kv : l.features) {
        if (!first) o += ',';
        first = false;
        o += "\n      \"" + json::Escape(kv.first) + "\": \"" +
             json::Escape(kv.second) + "\"";
    }
    o += (l.features.empty() ? "},\n" : "\n    },\n");
    o += "    \"nonce\": \"" + l.nonce + "\",\n";
    o += "    \"sig\": \"" + l.sig + "\"\n";
    o += "  }\n}\n";
    json_out = o;
    return true;
}

bool Check(const std::string& json_text, const std::string& pub_b64,
           const fp::FingerprintOutput* current, double threshold,
           LicenseCheck& out, std::string& err) {
    out = LicenseCheck{};
    LicenseData l;
    if (!ParseLicense(json_text, l, err)) {
        out.reasons.push_back("format: " + err);
        return false;
    }
    out.format_ok = true;
    out.signature_ok = VerifySignature(l, pub_b64);
    if (!out.signature_ok) out.reasons.push_back("签名校验失败");
    if (!l.expires_at.empty() && TodayUtc() > l.expires_at) {
        out.expired = true;
        out.reasons.push_back("已于 " + l.expires_at + " 过期");
    }
    if (l.bound()) {
        if (current != nullptr) {
            out.binding_checked = true;
            fp::FingerprintOutput lic_fp;
            lic_fp.master = l.fingerprint;
            lic_fp.sub = l.sub;
            out.similarity = fp::Similarity(lic_fp, *current);
            out.binding_ok = out.similarity >= threshold;
            if (!out.binding_ok) {
                out.reasons.push_back("机器不匹配：相似度 " +
                                      std::to_string(out.similarity) + " < 阈值 " +
                                      std::to_string(threshold));
            }
        } else {
            out.reasons.push_back("未提供当前机器指纹，绑定未校验");
        }
    }
    return out.valid();
}

std::string BuildCheckJson(const LicenseCheck& res, const LicenseData* l,
                           const double threshold) {
    std::string o = "{\n";
    o += "  \"valid\": " + std::string(res.valid() ? "true" : "false") + ",\n";
    o += "  \"format_ok\": " + std::string(res.format_ok ? "true" : "false") + ",\n";
    o += "  \"signature_ok\": " + std::string(res.signature_ok ? "true" : "false") + ",\n";
    o += "  \"bound\": " + std::string(l && l->bound() ? "true" : "false") + ",\n";
    o += "  \"binding_checked\": " + std::string(res.binding_checked ? "true" : "false") + ",\n";
    o += "  \"binding_ok\": " + std::string(res.binding_ok ? "true" : "false") + ",\n";
    o += "  \"expired\": " + std::string(res.expired ? "true" : "false") + ",\n";
    char num[64];
    std::snprintf(num, sizeof num, "%.4f", res.similarity);
    o += "  \"similarity\": " + std::string(num) + ",\n";
    std::snprintf(num, sizeof num, "%.2f", threshold);
    o += "  \"threshold\": " + std::string(num) + ",\n";
    o += "  \"licensee\": \"" + (l ? json::Escape(l->licensee) : "") + "\",\n";
    o += "  \"issued_at\": \"" + (l ? l->issued_at : "") + "\",\n";
    o += "  \"expires_at\": \"" + (l ? l->expires_at : "") + "\",\n";
    o += "  \"reasons\": [";
    for (size_t i = 0; i < res.reasons.size(); ++i) {
        o += std::string(i ? "," : "") + "\n    \"" + json::Escape(res.reasons[i]) + "\"";
    }
    o += res.reasons.empty() ? "]\n" : "\n  ]\n";
    o += "}";
    return o;
}

std::string TodayUtc() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char b[16];
    std::snprintf(b, sizeof b, "%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    return b;
}

} // namespace lic
