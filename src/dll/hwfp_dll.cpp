// ============================================================
// hwfp.dll 导出实现（C ABI；语义见 hwfp_dll.h）
// ============================================================
#define HWFP_BUILD_DLL
#include "dll/hwfp_dll.h"
#include "cli/report.h"
#include "core/collect_runner.h"
#include "core/version.h"
#include "license/license.h"
#include <cstdlib>
#include <cstring>

namespace {

char* DupOut(const std::string& s) {
    // 输出缓冲按 CRT 堆分配，Hwfp_Free 用同一堆释放（/MT 下与宿主 CRT 隔离）
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (!p) return nullptr;
    std::memcpy(p, s.c_str(), s.size() + 1);
    return p;
}

int SetOut(char** out, const std::string& s) {
    if (!out) return 2;
    *out = nullptr;
    char* p = DupOut(s);
    if (!p) return 3;   // 分配失败按失败语义，不当作参数错误
    *out = p;
    return 0;
}

int RunCollect(const HwfpConfig& cfg, char** out_json) {
    if (!out_json) return 2;
    *out_json = nullptr;
    CollectorManager::RunResult rr;
    fp::FingerprintOutput fp;
    if (!runner::CollectFingerprint(cfg, rr, fp)) return 3;
    return SetOut(out_json, report::BuildJson(rr, fp, kHwfpVersion));
}

} // namespace

HWFP_API const char* Hwfp_Version(void) {
    return kHwfpVersion;
}

HWFP_API int Hwfp_Collect(char** out_json) {
    HwfpConfig cfg;   // 默认配置：不读文件（库行为可预期）
    return RunCollect(cfg, out_json);
}

HWFP_API int Hwfp_CollectWithConfig(const char* config_json_utf8, char** out_json) {
    if (!out_json) return 2;
    *out_json = nullptr;   // 出参入口即归零：任何早退路径都保证 *out 为空
    if (!config_json_utf8) return 2;
    HwfpConfig cfg;
    std::string err;
    if (!cfg.LoadFromText(config_json_utf8, err)) return 2;
    return RunCollect(cfg, out_json);
}

HWFP_API int Hwfp_CheckLicense(const char* license_json_utf8,
                               const char* pubkey_b64,
                               double threshold,
                               char** out_result_json) {
    if (!out_result_json) return 2;
    *out_result_json = nullptr;
    if (!license_json_utf8 || !pubkey_b64) return 2;
    if (threshold <= 0.0 || threshold > 1.0) threshold = 0.85;

    lic::LicenseData l;
    std::string err;
    if (!lic::ParseLicense(license_json_utf8, l, err)) {
        lic::LicenseCheck res;
        res.reasons.push_back("format: " + err);
        const int rc = SetOut(out_result_json, lic::BuildCheckJson(res, nullptr, threshold));
        return rc ? rc : 5;
    }

    // 绑定授权需要本机指纹；签名有效时才值得花采集开销（与 CLI 口径一致）
    fp::FingerprintOutput current;
    bool sig_precheck_ok = lic::VerifySignature(l, pubkey_b64);
    if (sig_precheck_ok && l.bound()) {
        HwfpConfig cfg;
        CollectorManager::RunResult rr;
        if (!runner::CollectFingerprint(cfg, rr, current)) return 3;
    }
    lic::LicenseCheck res;
    lic::Check(license_json_utf8, pubkey_b64,
               (sig_precheck_ok && l.bound()) ? &current : nullptr,
               threshold, res, err);
    const int rc = SetOut(out_result_json, lic::BuildCheckJson(res, &l, threshold));
    if (rc) return rc;
    if (!res.format_ok || !res.signature_ok) return 5;
    return res.valid() ? 0 : 6;
}

HWFP_API void Hwfp_Free(char* p) {
    std::free(p);
}
