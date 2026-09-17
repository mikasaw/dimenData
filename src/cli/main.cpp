// ============================================================
// hwfp.exe —— Windows 硬件信息采集与设备指纹 CLI
//
// 用法:
//   hwfp.exe [--config <path>] [-o <path>] [--text]
//   hwfp.exe --verify <old-report.json> [--config <path>]
//   hwfp.exe keygen --privkey <path> --pubkey <path>
//   hwfp.exe license --issue ... | --check <license.json> ...
//   hwfp.exe --fields
//   hwfp.exe --version
//
// 退出码: 0 成功/授权有效；2 参数/配置错误；3 采集失败、完整性校验失败
//         或密钥操作失败；4 --verify 时报告算法版本与当前不一致；
//         5 授权文件格式或签名无效；6 授权已过期或机器不匹配
// ============================================================
#include <windows.h>
#include "cli/report.h"
#include "core/collect_runner.h"
#include "core/config.h"
#include "core/field.h"
#include "core/json.h"
#include "core/textutil.h"
#include "core/version.h"
#include "fingerprint/fingerprint_engine.h"
#include "license/license.h"
#include "license/crypto.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

namespace {

constexpr const char* kToolVersion = kHwfpVersion;

int PrintUsage() {
    std::printf(
        "hwfp %s — Windows 硬件信息采集与设备指纹\n"
        "用法:\n"
        "  hwfp.exe [--config <path>] [-o <path>] [--text]\n"
        "      采集并生成设备指纹（默认输出 schema v1 JSON 到 stdout）\n"
        "      --config  配置文件（默认 config/hwfp.json，存在即加载）\n"
        "      -o        输出到文件\n"
        "      --text    人类可读摘要代替 JSON\n"
        "  hwfp.exe --verify <old-report.json> [--config <path>]\n"
        "      重新采集并与历史报告比对，输出整机指纹比对与相似度评分\n"
        "  hwfp.exe keygen --privkey <path> --pubkey <path>\n"
        "      生成授权密钥对（RSA-2048）：私钥签发用，公钥随程序分发\n"
        "  hwfp.exe license --issue --licensee <name> --privkey <path>\n"
        "            [--expires YYYY-MM-DD] [--floating] [-o <path>] [--config <path>]\n"
        "      签发授权文件（默认采集本机指纹绑定；--floating 为浮动授权）\n"
        "  hwfp.exe license --check <license.json> --pubkey <path> [--threshold 0.85]\n"
        "            [--config <path>]\n"
        "      校验授权：签名 + 有效期 + 机器绑定（组权重相似度阈值）\n"
        "  hwfp.exe --fields   列出全部字段键及默认权重\n"
        "  hwfp.exe --version  版本信息\n"
        "退出码: 0 成功/授权有效；2 参数/配置错误；3 采集失败、完整性校验失败或\n"
        "        密钥操作失败；4 --verify 时报告算法版本与当前不一致（完整性不可\n"
        "        判定）；5 授权文件格式或签名无效；6 授权已过期或机器不匹配\n",
        kToolVersion);
    return 0;
}

bool ReadFileText(const std::string& path, std::string& out, std::string& err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { err = "无法打开文件: " + path; return false; }
    std::ostringstream os;
    os << f.rdbuf();
    out = os.str();
    return true;
}

bool WriteFileText(const std::string& path, const std::string& text, std::string& err) {
    std::ofstream f(path, std::ios::binary);
    if (!f) { err = "无法写入文件: " + path; return false; }
    f.write(text.data(), (std::streamsize)text.size());
    return true;
}

// 配置加载：未显式给 --config 时，默认配置存在才加载；失败返回退出码
int LoadConfigOrExit(bool have_config, const std::string& config_path, HwfpConfig& cfg) {
    std::string err;
    if (!have_config) {
        std::ifstream f("config/hwfp.json");
        if (f) {
            f.close();
            if (!cfg.LoadFromFile("config/hwfp.json", err)) {
                std::fprintf(stderr, "配置错误: %s\n", err.c_str());
                return 2;
            }
        }
    } else if (!cfg.LoadFromFile(config_path, err)) {
        std::fprintf(stderr, "配置错误: %s\n", err.c_str());
        return 2;
    }
    return 0;
}

// 采集 + 指纹（collect 默认路径与 license 子命令共用）
bool CollectFingerprint(const HwfpConfig& cfg, CollectorManager::RunResult& rr,
                        fp::FingerprintOutput& fp_out) {
    return runner::CollectFingerprint(cfg, rr, fp_out);
}

int CmdFields() {
    for (int i = 0; i < GetFieldDefCount(); ++i) {
        const FieldDef& d = GetFieldDefs()[i];
        std::printf("%-24s group=%-6s strategy=%-17s weight=%d\n",
                    d.name, ToString(d.group), ToString(d.strategy), d.weight);
    }
    return 0;
}

// ---------- keygen 子命令 ----------

int CmdKeygen(int argc, char** argv) {
    std::string priv_path, pub_path;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--privkey" && i + 1 < argc) priv_path = argv[++i];
        else if (a == "--pubkey" && i + 1 < argc) pub_path = argv[++i];
        else {
            std::fprintf(stderr, "未知参数: %s（keygen 用法: keygen --privkey <p> --pubkey <p>）\n",
                         a.c_str());
            return 2;
        }
    }
    if (priv_path.empty() || pub_path.empty()) {
        std::fprintf(stderr, "keygen 需要 --privkey 与 --pubkey\n");
        return 2;
    }
    std::string priv, pub, err;
    unsigned long st = 0;
    if (!lic::GenerateKeyPair(priv, pub, &st)) {
        std::fprintf(stderr, "密钥生成失败 (NTSTATUS 0x%08lX)\n", st);
        return 3;
    }
    priv += "\n";
    pub += "\n";
    if (!WriteFileText(priv_path, priv, err) || !WriteFileText(pub_path, pub, err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return 3;
    }
    std::printf("已生成密钥对（RSA-2048）\n"
                "  私钥 %s  —— 签发授权用，妥善保管、勿随程序分发\n"
                "  公钥 %s  —— 随程序分发，校验授权用\n",
                priv_path.c_str(), pub_path.c_str());
    return 0;
}

// ---------- license 子命令 ----------

int CmdLicense(int argc, char** argv) {
    bool issue = false, floating = false, have_config = false;
    std::string check_path, licensee, privkey_path, pubkey_path, expires, out_path;
    std::string config_path;
    double threshold = 0.85;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--issue") issue = true;
        else if (a == "--check" && i + 1 < argc) check_path = argv[++i];
        else if (a == "--licensee" && i + 1 < argc) licensee = argv[++i];
        else if (a == "--privkey" && i + 1 < argc) privkey_path = argv[++i];
        else if (a == "--pubkey" && i + 1 < argc) pubkey_path = argv[++i];
        else if (a == "--expires" && i + 1 < argc) expires = argv[++i];
        else if (a == "--floating") floating = true;
        else if (a == "--threshold" && i + 1 < argc) threshold = std::strtod(argv[++i], nullptr);
        else if (a == "-o" && i + 1 < argc) out_path = argv[++i];
        else if (a == "--config" && i + 1 < argc) { config_path = argv[++i]; have_config = true; }
        else {
            std::fprintf(stderr, "未知参数: %s\n", a.c_str());
            return 2;
        }
    }
    if (issue != check_path.empty()) {
        // 合法组合：issue 且无 check 路径 / 非 issue 且有 check 路径
        std::fprintf(stderr, "license 需要 --issue 或 --check（二选一）\n");
        return 2;
    }
    if (threshold <= 0.0 || threshold > 1.0) {
        std::fprintf(stderr, "--threshold 应在 (0,1]\n");
        return 2;
    }

    if (issue) {
        if (licensee.empty() || privkey_path.empty()) {
            std::fprintf(stderr, "--issue 需要 --licensee 与 --privkey\n");
            return 2;
        }
        std::string priv_raw, priv_b64, err;
        if (!ReadFileText(privkey_path, priv_raw, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 2;
        }
        priv_b64 = textutil::Trim(priv_raw);

        lic::LicenseData l;
        l.licensee = licensee;
        l.issued_at = lic::TodayUtc();
        l.expires_at = expires;
        if (!lic::RandomHex(16, l.nonce)) {
            std::fprintf(stderr, "nonce 生成失败\n");
            return 3;
        }
        if (!floating) {
            HwfpConfig cfg;
            const int rc = LoadConfigOrExit(have_config, config_path, cfg);
            if (rc) return rc;
            CollectorManager::RunResult rr;
            fp::FingerprintOutput fp;
            if (!CollectFingerprint(cfg, rr, fp)) {
                std::fprintf(stderr, "采集失败：无法生成绑定指纹\n");
                return 3;
            }
            l.fingerprint = fp.master;
            l.sub = fp.sub;
        }
        std::string json_out;
        if (!lic::Issue(l, priv_b64, json_out, err)) {
            std::fprintf(stderr, "签发失败: %s\n", err.c_str());
            return 3;
        }
        if (out_path.empty()) out_path = "license.json";
        if (!WriteFileText(out_path, json_out, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 3;
        }
        std::printf("已签发 %s（%s，有效期至 %s）\n", out_path.c_str(),
                    l.bound() ? "绑定本机" : "浮动授权",
                    l.expires_at.empty() ? "永久" : l.expires_at.c_str());
        return 0;
    }

    // ---- 校验侧 ----
    if (pubkey_path.empty()) {
        std::fprintf(stderr, "--check 需要 --pubkey\n");
        return 2;
    }
    std::string lic_text, pub_raw, err;
    if (!ReadFileText(check_path, lic_text, err) ||
        !ReadFileText(pubkey_path, pub_raw, err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return 2;
    }
    const std::string pub_b64 = textutil::Trim(pub_raw);

    lic::LicenseData l;
    lic::LicenseCheck res;
    fp::FingerprintOutput current;
    bool sig_precheck_ok = false;
    const bool parsed = lic::ParseLicense(lic_text, l, err);
    if (parsed) {
        // 验签先行：签名无效时快速失败，不做昂贵采集
        sig_precheck_ok = lic::VerifySignature(l, pub_b64);
        if (sig_precheck_ok && l.bound()) {
            HwfpConfig cfg;
            const int rc = LoadConfigOrExit(have_config, config_path, cfg);
            if (rc) return rc;
            CollectorManager::RunResult rr;
            if (!CollectFingerprint(cfg, rr, current)) {
                std::fprintf(stderr, "采集失败：无法生成绑定指纹\n");
                return 3;
            }
        }
        lic::Check(lic_text, pub_b64,
                   (sig_precheck_ok && l.bound()) ? &current : nullptr,
                   threshold, res, err);
    } else {
        res.reasons.push_back(std::string("格式: ") + err);
    }

    std::printf("%s\n", lic::BuildCheckJson(res, parsed ? &l : nullptr, threshold).c_str());
    if (!res.format_ok || !res.signature_ok) return 5;
    return res.valid() ? 0 : 6;
}

} // namespace

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    // 子命令派发（默认路径 = 无子命令的采集）
    if (argc > 1) {
        const std::string cmd = argv[1];
        if (cmd == "keygen") return CmdKeygen(argc, argv);
        if (cmd == "license") return CmdLicense(argc, argv);
    }

    std::string config_path, out_path, verify_path;
    bool text_mode = false, have_config = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--version") { std::printf("hwfp %s\n", kToolVersion); return 0; }
        if (a == "--help" || a == "-h") return PrintUsage();
        if (a == "--fields")  return CmdFields();
        if (a == "--text")    { text_mode = true; continue; }
        if (a == "--config" && i + 1 < argc) { config_path = argv[++i]; have_config = true; continue; }
        if (a == "-o" && i + 1 < argc) { out_path = argv[++i]; continue; }
        if (a == "--verify" && i + 1 < argc) { verify_path = argv[++i]; continue; }
        std::fprintf(stderr, "未知参数: %s（--help 见用法）\n", a.c_str());
        return 2;
    }
    if (!verify_path.empty() && text_mode) {
        std::fprintf(stderr, "--verify 与 --text 不可同时使用\n");
        return 2;
    }

    HwfpConfig cfg;
    {
        const int rc = LoadConfigOrExit(have_config, config_path, cfg);
        if (rc) return rc;
    }
    if (cfg.text_mode) text_mode = true;
    if (!cfg.output_path.empty() && out_path.empty()) out_path = cfg.output_path;

    // verify 重算需要权重口径；CollectFingerprint 内部也会应用一次（幂等、开销可忽略）
    const auto applied = runner::ApplyConfig(cfg);

    CollectorManager::RunResult rr;
    fp::FingerprintOutput fingerprint;
    if (!CollectFingerprint(cfg, rr, fingerprint)) {
        std::fprintf(stderr, "采集失败：无任何字段产出\n");
        return 3;
    }

    if (!verify_path.empty()) {
        std::string old_text, err;
        if (!ReadFileText(verify_path, old_text, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 2;
        }
        MergedResults old_merged;
        fp::FingerprintOutput old_fp;
        if (!report::ParseReport(old_text, old_merged, old_fp, err)) {
            std::fprintf(stderr, "历史报告解析失败: %s\n", err.c_str());
            return 2;
        }
        // 完整性校验（T8 验收 P0 修正）：从回读字段重算指纹并与报告记录值比对——
        // 报告字段被篡改时重算值与记录值不一致，integrity=false 且 match 不可信
        const auto recomputed = fp::ComputeFingerprint(old_merged,
                        applied.weights.empty() ? nullptr : &applied.weights);
        // 算法版本闸门：字段集/权重变更会使"重算值 == 记录值"不再成立，
        // 此时完整性不可判定（既非通过也非篡改），单独报告并给退出码 4。
        // match/similarity 不受影响：两侧都按当前算法计算，回答"是否同一台机器"。
        const bool algo_same = (old_fp.algo == fp::kAlgoVersion);
        const bool integrity = algo_same && recomputed.master == old_fp.master;
        const double sim = fp::Similarity(fingerprint, recomputed,
                        applied.weights.empty() ? nullptr : &applied.weights);
        const bool match = fingerprint.master == recomputed.master;
        std::printf("{\n");
        std::printf("  \"master\": \"%s\",\n", fingerprint.master.c_str());
        std::printf("  \"old_master_recorded\": \"%s\",\n", old_fp.master.c_str());
        std::printf("  \"old_master_recomputed\": \"%s\",\n", recomputed.master.c_str());
        std::printf("  \"algo\": {\"recorded\": %d, \"current\": %d},\n",
                    old_fp.algo, fp::kAlgoVersion);
        std::printf("  \"algorithm_changed\": %s,\n", algo_same ? "false" : "true");
        // 配置覆盖提示：重算用当前配置的权重，须与生成报告时一致，否则 integrity 无意义
        std::printf("  \"weights_override\": %s,\n",
                    applied.weights.empty() ? "false" : "true");
        if (algo_same)
            std::printf("  \"integrity\": %s,\n", integrity ? "true" : "false");
        else
            std::printf("  \"integrity\": null,\n");   // 算法已演进，不可判定
        std::printf("  \"match\": %s,\n", match ? "true" : "false");
        std::printf("  \"similarity\": %.4f\n", sim);
        std::printf("}\n");
        if (!algo_same) return 4;   // 算法版本不一致：完整性不可校验
        return integrity ? 0 : 3;   // 报告不自洽视为校验失败
    }

    std::string output;
    if (text_mode) {
        std::ostringstream os;
        os << "fingerprint: " << fingerprint.master << "\n";
        for (const auto& g : fingerprint.sub)
            os << "  " << g.first << ": " << g.second << "\n";
        os << "fields: " << rr.instances << " instances, " << (int)rr.ms << " ms\n";
        for (const auto& kv : rr.merged)
            for (const auto& r : kv.second) {
                const FieldDef* def = FindFieldDef(kv.first);
                os << "[" << (r.channel.empty() ? "-" : r.channel) << "] "
                   << (def ? def->name : "?") << "[" << r.index << "] = "
                   << (r.value.empty() ? "<empty>" : r.value) << "\n";
            }
        output = os.str();
    } else {
        output = report::BuildJson(rr, fingerprint, kToolVersion);
    }

    if (out_path.empty()) {
        std::fwrite(output.data(), 1, output.size(), stdout);
        std::fputc('\n', stdout);
    } else {
        std::ofstream f(out_path, std::ios::binary);
        if (!f) { std::fprintf(stderr, "无法写入输出文件: %s\n", out_path.c_str()); return 2; }
        f.write(output.data(), (std::streamsize)output.size());
        std::printf("已写入 %s\n", out_path.c_str());
    }
    return 0;
}
