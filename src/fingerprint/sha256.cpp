#include "fingerprint/sha256.h"
#include <windows.h>
#include <bcrypt.h>
#include "core/textutil.h"

#pragma comment(lib, "bcrypt")

namespace fp {

bool Sha256Raw(const std::string& data, unsigned char digest[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return false;
    BCRYPT_HASH_HANDLE h = nullptr;
    const bool ok =
        BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0)) &&
        BCRYPT_SUCCESS(BCryptHashData(h, (PUCHAR)data.data(), (ULONG)data.size(), 0)) &&
        BCRYPT_SUCCESS(BCryptFinishHash(h, digest, 32, 0));
    if (h) BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

std::string Sha256Hex(const std::string& data) {
    unsigned char digest[32];
    if (!Sha256Raw(data, digest)) return {};
    return textutil::Hex(digest, sizeof(digest));
}

} // namespace fp
