// ============================================================
// T10 授权模块单测：base64、RSA 签验签、canonical 稳定性与注入防线、
//     签发→校验往返、篡改检出、绑定阈值、过期判定
// 测试中的指纹/子指纹全部为合成值；RSA 密钥对用懒加载单例（生成 ~百毫秒）
// ============================================================
#include "tests/test_util.h"
#include "license/crypto.h"
#include "license/license.h"
#include "fingerprint/fingerprint_engine.h"
#include <cstring>
#include <string>

namespace {

// 64 位十六进制合成指纹（形似真值、内容为模式串）
const char* kFpA = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90";
const char* kSubBoardA = "B0A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1";
const char* kSubCpuA = "C0A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1B2A1";

// 测试密钥对懒加载（进程内只生成一次）
struct TestKeys {
    std::string priv, pub;        // 签发方
    std::string priv2, pub2;      // "另一把钥匙"（误配/攻击方）
    bool ok = false;
    TestKeys() {
        ok = lic::GenerateKeyPair(priv, pub) && lic::GenerateKeyPair(priv2, pub2);
    }
};

const TestKeys& Keys() {
    static TestKeys k;
    return k;
}

lic::LicenseData MakeLicense() {
    lic::LicenseData l;
    l.licensee = "测试客户 Acme Co.";
    l.issued_at = "2026-09-18";
    l.expires_at = "2027-09-18";
    l.fingerprint = kFpA;
    l.sub["board"] = kSubBoardA;
    l.sub["cpu"] = kSubCpuA;
    l.features["seats"] = "5";
    l.nonce = "0123456789ABCDEF0123456789ABCDEF";
    return l;
}

fp::FingerprintOutput FpFromLicense(const lic::LicenseData& l) {
    fp::FingerprintOutput fp;
    fp.master = l.fingerprint;
    fp.sub = l.sub;
    return fp;
}

// 同一机器的"当前指纹"（与授权内容一致）
fp::FingerprintOutput MachineA() { return FpFromLicense(MakeLicense()); }

} // namespace

TEST(base64, rfc4648_vectors) {
    CHECK_STREQ(lic::Base64Encode((const unsigned char*)"", 0), "");
    CHECK_STREQ(lic::Base64Encode((const unsigned char*)"f", 1), "Zg==");
    CHECK_STREQ(lic::Base64Encode((const unsigned char*)"fo", 2), "Zm8=");
    CHECK_STREQ(lic::Base64Encode((const unsigned char*)"foo", 3), "Zm9v");
    CHECK_STREQ(lic::Base64Encode((const unsigned char*)"foob", 4), "Zm9vYg==");
    CHECK_STREQ(lic::Base64Encode((const unsigned char*)"fooba", 5), "Zm9vYmE=");
    CHECK_STREQ(lic::Base64Encode((const unsigned char*)"foobar", 6), "Zm9vYmFy");
    const char* v[] = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
    for (const char* s : v) {
        std::string dec;
        CHECK(lic::Base64Decode(lic::Base64Encode((const unsigned char*)s, strlen(s)), dec));
        CHECK_STREQ(dec, s);
    }
    std::string dec;
    // 空白容忍 + 非法字符拒绝
    CHECK(lic::Base64Decode("Zm9v\n\tYmFy\r\n", dec));
    CHECK_STREQ(dec, "foobar");
    CHECK(!lic::Base64Decode("Zm9*v", dec));
}

TEST(crypto, rsa_sign_verify) {
    ASSERT(Keys().ok);
    const std::string msg = "HWFP-LICENSE-V1\nlicensee=测试客户";
    std::string sig;
    CHECK(lic::Sign(Keys().priv, msg, sig));
    CHECK(lic::Verify(Keys().pub, msg, sig));
    CHECK(!lic::Verify(Keys().pub, msg + "!", sig));            // 数据被改
    std::string sig2;
    CHECK(lic::Sign(Keys().priv, msg + "!", sig2));
    CHECK(!lic::Verify(Keys().pub, msg, sig2));                 // 摘要随之变化
    CHECK(!lic::Verify(Keys().pub2, msg, sig));                 // 换公钥
    CHECK(!lic::Sign("not-base64!!", msg, sig2));               // 私钥解码失败
}

TEST(license, canonical_is_deterministic) {
    lic::LicenseData a = MakeLicense();
    lic::LicenseData b = MakeLicense();
    // map 插入序不同不影响 canonical（按键排序）
    b.sub.clear();
    b.sub["cpu"] = kSubCpuA;
    b.sub["board"] = kSubBoardA;
    CHECK_STREQ(lic::BuildCanonical(a), lic::BuildCanonical(b));
    // 头部与行结构
    const std::string c = lic::BuildCanonical(a);
    CHECK(c.compare(0, 16, "HWFP-LICENSE-V1\n") == 0);
    CHECK(c.find("\nlicensee=测试客户 Acme Co.\n") != std::string::npos);
    CHECK(c.find("\nsub=board=" + std::string(kSubBoardA) + ";cpu=" + kSubCpuA) !=
          std::string::npos);
    CHECK(c.find("\nfeatures=seats=5\n") != std::string::npos);
    CHECK(c.compare(c.size() - 6, 6, "nonce=") != 0);   // nonce 是最后一行（有值）
}

TEST(license, issue_and_check_valid) {
    ASSERT(Keys().ok);
    lic::LicenseData l = MakeLicense();
    std::string text, err;
    CHECK(lic::Issue(l, Keys().priv, text, err));
    CHECK(!l.sig.empty());

    // 同机 + 默认阈值 → 有效
    fp::FingerprintOutput cur = MachineA();
    lic::LicenseCheck res;
    CHECK(lic::Check(text, Keys().pub, &cur, 0.85, res, err));
    CHECK(res.valid());
    CHECK(res.format_ok && res.signature_ok && res.binding_checked && res.binding_ok);
    CHECK(res.similarity >= 0.85);

    // 绑定授权但不给当前机器 → 签名有效、绑定未判定
    lic::LicenseCheck res2;
    CHECK(lic::Check(text, Keys().pub, nullptr, 0.85, res2, err));
    CHECK(res2.signature_ok && !res2.binding_checked);
    CHECK(res2.valid());

    // 换公钥 → 验签失败
    lic::LicenseCheck res3;
    CHECK(!lic::Check(text, Keys().pub2, &cur, 0.85, res3, err));
    CHECK(!res3.signature_ok && !res3.valid());
}

TEST(license, tamper_detection) {
    ASSERT(Keys().ok);
    lic::LicenseData l = MakeLicense();
    std::string text, err;
    CHECK(lic::Issue(l, Keys().priv, text, err));
    fp::FingerprintOutput cur = MachineA();

    // 等长替换保持 JSON 合法：licensee、features 值、sub 值各自被篡改 → 验签必须失败
    const std::string sub_b = "\"" + std::string(kSubBoardA) + "\"";
    auto patched = [&text](const std::string& from, const std::string& to) {
        std::string t = text;
        const size_t p = t.find(from);
        if (p == std::string::npos) return std::string("missing:" + from);
        return t.replace(p, from.size(), to);
    };
    for (const std::string& bad : {
             patched("Acme Co.", "Acme CO."),                              // 客户名被改
             patched("\"seats\": \"5\"", "\"seats\": \"9\""),              // 功能位被改
             patched(sub_b, "\"" + std::string(64, '9') + "\""),           // 子指纹被改
         }) {
        lic::LicenseCheck res;
        lic::Check(bad, Keys().pub, &cur, 0.85, res, err);
        CHECK(!res.signature_ok && !res.valid());
    }
    // 签名串本身被改（保持 base64 合法）
    std::string bad_sig = text;
    {
        const size_t p = bad_sig.find("\"sig\": \"");
        if (p != std::string::npos) bad_sig[p + 9] =
            (bad_sig[p + 9] == 'A') ? 'B' : 'A';
        lic::LicenseCheck res;
        lic::Check(bad_sig, Keys().pub, &cur, 0.85, res, err);
        CHECK(!res.signature_ok);
    }
}

TEST(license, binding_threshold) {
    ASSERT(Keys().ok);
    lic::LicenseData l = MakeLicense();
    std::string text, err;
    CHECK(lic::Issue(l, Keys().priv, text, err));

    // 换了一块主板（board 子指纹变化）→ 相似度下降
    fp::FingerprintOutput cur = MachineA();
    cur.sub["board"] = std::string(64, 'D');
    lic::LicenseCheck res;
    lic::Check(text, Keys().pub, &cur, 0.85, res, err);
    CHECK(res.binding_checked && !res.binding_ok && !res.valid());
    CHECK(res.similarity < 0.85);
    // 阈值放到最低（0 已被参数校验拒绝，用 0.01）→ 通过
    lic::LicenseCheck res2;
    CHECK(lic::Check(text, Keys().pub, &cur, 0.01, res2, err));
    CHECK(res2.binding_ok && res2.valid());

    // 浮动授权：任何机器都通过（不判绑定）
    lic::LicenseData fl = MakeLicense();
    fl.fingerprint.clear();
    fl.sub.clear();
    std::string fl_text;
    CHECK(lic::Issue(fl, Keys().priv, fl_text, err));
    lic::LicenseCheck res3;
    CHECK(lic::Check(fl_text, Keys().pub, &cur, 0.85, res3, err));
    CHECK(!res3.binding_checked && res3.valid());
}

TEST(license, expiry) {
    ASSERT(Keys().ok);
    fp::FingerprintOutput cur = MachineA();
    // 已过期
    {
        lic::LicenseData l = MakeLicense();
        l.expires_at = "2001-01-01";
        std::string text, err;
        CHECK(lic::Issue(l, Keys().priv, text, err));
        lic::LicenseCheck res;
        CHECK(!lic::Check(text, Keys().pub, &cur, 0.85, res, err));
        CHECK(res.expired && res.signature_ok && !res.valid());
    }
    // 长期有效
    {
        lic::LicenseData l = MakeLicense();
        l.expires_at = "2099-12-31";
        std::string text, err;
        CHECK(lic::Issue(l, Keys().priv, text, err));
        lic::LicenseCheck res;
        CHECK(lic::Check(text, Keys().pub, &cur, 0.85, res, err));
        CHECK(!res.expired && res.valid());
    }
    // 永久（空 expires_at）
    {
        lic::LicenseData l = MakeLicense();
        l.expires_at.clear();
        std::string text, err;
        CHECK(lic::Issue(l, Keys().priv, text, err));
        lic::LicenseCheck res;
        CHECK(lic::Check(text, Keys().pub, &cur, 0.85, res, err));
        CHECK(res.valid());
    }
    CHECK_EQ((int)lic::TodayUtc().size(), 10);   // YYYY-MM-DD
}

TEST(license, rejects_malformed_and_injection) {
    ASSERT(Keys().ok);
    lic::LicenseCheck res;
    std::string err;
    // 非 JSON / 缺 license 对象 / 错 schema
    CHECK(!lic::Check("not json", Keys().pub, nullptr, 0.85, res, err));
    CHECK(!res.format_ok);
    CHECK(!lic::Check("{\"a\":1}", Keys().pub, nullptr, 0.85, res, err));
    CHECK(!lic::Check("{\"license\":{\"schema\":2}}", Keys().pub, nullptr, 0.85, res, err));

    // 签发侧字段防线
    lic::LicenseData l = MakeLicense();
    l.licensee = "多行\n客户";
    std::string text;
    CHECK(!lic::Issue(l, Keys().priv, text, err));       // 值含换行
    l = MakeLicense();
    l.licensee.clear();
    CHECK(!lic::Issue(l, Keys().priv, text, err));       // 空 licensee
    l = MakeLicense();
    l.fingerprint = "XYZ";                               // 指纹形态非法
    CHECK(!lic::Issue(l, Keys().priv, text, err));
    l = MakeLicense();
    l.expires_at = "2027/09/18";                         // 日期形态非法
    CHECK(!lic::Issue(l, Keys().priv, text, err));
    l = MakeLicense();
    l.features["a;b"] = "1";                             // 分隔符注入
    CHECK(!lic::Issue(l, Keys().priv, text, err));

    // 解析侧同样拒绝注入形态的载荷（即便 JSON 合法）
    lic::LicenseData p;
    CHECK(!lic::ParseLicense(
        "{\"license\":{\"schema\":1,\"licensee\":\"a\\nb\",\"nonce\":\"x\"}}",
        p, err));
        CHECK(!lic::ParseLicense(
        "{\"license\":{\"schema\":1,\"licensee\":\"ok\",\"nonce\":\"x\","
        "\"features\":{\"a=b\":\"1\"}}}", p, err));
}
