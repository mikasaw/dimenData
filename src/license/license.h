// ============================================================
// 授权模块 · 离线授权文件（schema v1）
//
// 文件 = license 对象（授权载荷字段 + sig）。sig 是对 canonical 文本的
// RSA-2048 签名（base64）；canonical 按固定键序手工拼装、与文件字节序
// 无关，字段增删必须升 schema 版本并同步两侧：
//
//   HWFP-LICENSE-V1
//   licensee=<客户标识，单行>
//   issued_at=<YYYY-MM-DD>
//   expires_at=<YYYY-MM-DD 或空>       ; 空 = 永久
//   fingerprint=<64hex 或空>           ; 绑定整机指纹；空 = 浮动授权
//   sub=<组=子指纹;...>                ; 按组名升序；参与绑定相似度
//   features=<k=v;...>                 ; 按键升序；语义由调用方定义
//   nonce=<签发侧随机串>               ; 防同一内容重复签发
//
// 校验 = 验签 + 过期判定 + 绑定校验（重算当前机器指纹，与授权内
// 整机/子指纹做组权重相似度，>= 阈值视为同一台机器；默认 0.85，
// 容忍内存条数/外设等小硬件变更——与 --verify 的相似度口径一致）。
// 防线：sub/features 参与签名，篡改任一字段即验签失败；
// canonical 注入（值内含换行/分隔符）在解析与签发两侧均被拒绝。
// ============================================================
#pragma once
#include <map>
#include <string>
#include <vector>
#include "fingerprint/fingerprint_engine.h"

namespace lic {

struct LicenseData {
    std::string licensee;
    std::string issued_at;      // YYYY-MM-DD
    std::string expires_at;     // 空 = 永久
    std::string fingerprint;    // 绑定整机指纹（64 hex）；空 = 浮动授权
    std::map<std::string, std::string> sub;       // 组 → 子指纹
    std::map<std::string, std::string> features;  // 功能位
    std::string nonce;
    std::string sig;            // base64 签名

    bool bound() const { return !fingerprint.empty(); }
};

struct LicenseCheck {
    bool format_ok = false;      // JSON/schema/canonical 字符合法
    bool signature_ok = false;
    bool binding_checked = false;  // 授权绑定机器且提供了当前机器指纹才为 true
    bool binding_ok = false;
    bool expired = false;
    double similarity = 0.0;     // 绑定校验的组权重相似度
    std::vector<std::string> reasons;

    // binding_checked=false（浮动授权或未提供机器指纹）时绑定不参与判定
    bool valid() const {
        return format_ok && signature_ok && !expired &&
               (!binding_checked || binding_ok);
    }
};

// 签发与校验两侧共用的 canonical 文本
std::string BuildCanonical(const LicenseData& l);

// 发布侧字段校验（键序注入/空字段/形态）——Issue 与 Parse 共用同一套规则
bool ValidateFields(const LicenseData& l, std::string& err);

// 解析授权文件 JSON（不验签）
bool ParseLicense(const std::string& json_text, LicenseData& l, std::string& err);

// 验签（对重建的 canonical）
bool VerifySignature(const LicenseData& l, const std::string& pub_b64,
                     unsigned long* status = nullptr);

// 签发：字段校验 → 签名 → 序列化为授权文件 JSON（含 sig）
bool Issue(LicenseData& l, const std::string& priv_b64,
           std::string& json_out, std::string& err);

// 完整校验。current 为 nullptr 时跳过绑定校验（binding_checked=false）。
// 返回值 = out.valid()
bool Check(const std::string& json_text, const std::string& pub_b64,
           const fp::FingerprintOutput* current, double threshold,
           LicenseCheck& out, std::string& err);

// 校验结果 → 明细 JSON（CLI license --check 与 hwfp.dll 共用输出形态；
// l 传 nullptr 时 licensee/issued_at/expires_at 输出空串）
std::string BuildCheckJson(const LicenseCheck& res, const LicenseData* l,
                           double threshold);

// 今天（UTC，YYYY-MM-DD），过期判定基准
std::string TodayUtc();

} // namespace lic
