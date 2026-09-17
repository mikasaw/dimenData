#include "license/crypto.h"
#include "core/textutil.h"
#include "fingerprint/sha256.h"
#include <windows.h>
#include <bcrypt.h>
#include <vector>

#pragma comment(lib, "bcrypt")

namespace lic {

// ---------- base64（RFC 4648） ----------

std::string Base64Encode(const unsigned char* d, size_t n) {
    static const char* kA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((n + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        const unsigned v = ((unsigned)d[i] << 16) | ((unsigned)d[i + 1] << 8) | d[i + 2];
        out += kA[(v >> 18) & 63];
        out += kA[(v >> 12) & 63];
        out += kA[(v >> 6) & 63];
        out += kA[v & 63];
    }
    const size_t rem = n - i;
    if (rem == 1) {
        const unsigned v = (unsigned)d[i] << 16;
        out += kA[(v >> 18) & 63];
        out += kA[(v >> 12) & 63];
        out += "==";
    } else if (rem == 2) {
        const unsigned v = ((unsigned)d[i] << 16) | ((unsigned)d[i + 1] << 8);
        out += kA[(v >> 18) & 63];
        out += kA[(v >> 12) & 63];
        out += kA[(v >> 6) & 63];
        out += '=';
    }
    return out;
}

bool Base64Decode(const std::string& text, std::string& out) {
    out.clear();
    out.reserve(text.size() / 4 * 3);
    unsigned buf = 0;
    int bits = 0;
    for (const char c : text) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=') break;   // padding 后忽略其余（本模块只在尾部产生 padding）
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else return false;
        buf = (buf << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += (char)((buf >> bits) & 0xFF);
        }
    }
    return true;
}

// ---------- CNG RSA ----------

namespace {

// RAII：算法提供者与密钥句柄
struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    explicit AlgHandle(LPCWSTR algo) {
        BCryptOpenAlgorithmProvider(&h, algo, nullptr, 0);
    }
    ~AlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
    bool ok() const { return h != nullptr; }
};

struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() { if (h) BCryptDestroyKey(h); }
};

unsigned long ExportKey(BCRYPT_KEY_HANDLE key, LPCWSTR blob_type, std::string& out_b64) {
    unsigned long cb = 0;
    unsigned long st = BCryptExportKey(key, nullptr, blob_type, nullptr, 0, &cb, 0);
    if (st) return st;
    std::vector<unsigned char> blob(cb);
    st = BCryptExportKey(key, nullptr, blob_type, blob.data(), cb, &cb, 0);
    if (st) return st;
    out_b64 = Base64Encode(blob.data(), blob.size());
    return 0;
}

unsigned long ImportKey(AlgHandle& alg, LPCWSTR blob_type,
                        const std::string& blob, KeyHandle& key) {
    return BCryptImportKeyPair(alg.h, nullptr, blob_type, &key.h,
                               (PUCHAR)blob.data(), (ULONG)blob.size(), 0);
}

} // namespace

bool GenerateKeyPair(std::string& priv_b64, std::string& pub_b64,
                     unsigned long* status) {
    priv_b64.clear();
    pub_b64.clear();
    if (status) *status = 0;
    AlgHandle alg(BCRYPT_RSA_ALGORITHM);
    if (!alg.ok()) return false;
    KeyHandle key;
    unsigned long st = BCryptGenerateKeyPair(alg.h, &key.h, 2048, 0);
    if (!st) st = BCryptFinalizeKeyPair(key.h, 0);
    if (!st) st = ExportKey(key.h, BCRYPT_RSAFULLPRIVATE_BLOB, priv_b64);
    if (!st) st = ExportKey(key.h, BCRYPT_RSAPUBLIC_BLOB, pub_b64);
    if (status) *status = st;
    return !st && !priv_b64.empty() && !pub_b64.empty();
}

bool Sign(const std::string& priv_b64, const std::string& data,
          std::string& sig_b64, unsigned long* status) {
    sig_b64.clear();
    if (status) *status = 0;
    std::string blob;
    if (!Base64Decode(priv_b64, blob)) return false;
    unsigned char digest[32];
    if (!fp::Sha256Raw(data, digest)) return false;
    AlgHandle alg(BCRYPT_RSA_ALGORITHM);
    if (!alg.ok()) return false;
    KeyHandle key;
    unsigned long st = ImportKey(alg, BCRYPT_RSAFULLPRIVATE_BLOB, blob, key);
    if (!st) {
        unsigned char sig[256];
        unsigned long cb = 0;
        BCRYPT_PKCS1_PADDING_INFO pad{ BCRYPT_SHA256_ALGORITHM };
        st = BCryptSignHash(key.h, &pad, digest, sizeof digest,
                            sig, sizeof sig, &cb, BCRYPT_PAD_PKCS1);
        if (!st) sig_b64 = Base64Encode(sig, cb);
    }
    if (status) *status = st;
    return !st;
}

bool Verify(const std::string& pub_b64, const std::string& data,
            const std::string& sig_b64, unsigned long* status) {
    if (status) *status = 0;
    std::string keyblob, sig;
    if (!Base64Decode(pub_b64, keyblob) || !Base64Decode(sig_b64, sig)) return false;
    unsigned char digest[32];
    if (!fp::Sha256Raw(data, digest)) return false;
    AlgHandle alg(BCRYPT_RSA_ALGORITHM);
    if (!alg.ok()) return false;
    KeyHandle key;
    unsigned long st = ImportKey(alg, BCRYPT_RSAPUBLIC_BLOB, keyblob, key);
    if (!st) {
        BCRYPT_PKCS1_PADDING_INFO pad{ BCRYPT_SHA256_ALGORITHM };
        st = BCryptVerifySignature(key.h, &pad, digest, sizeof digest,
                                   (PUCHAR)sig.data(), (ULONG)sig.size(),
                                   BCRYPT_PAD_PKCS1);
    }
    if (status) *status = st;
    return !st;
}

bool RandomHex(size_t bytes, std::string& out_hex) {
    out_hex.clear();
    if (bytes == 0 || bytes > 256) return false;
    std::vector<unsigned char> b(bytes);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, b.data(), (ULONG)bytes,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return false;
    out_hex = textutil::Hex(b.data(), b.size());
    return true;
}

} // namespace lic
