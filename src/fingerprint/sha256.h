// ============================================================
// SHA-256 封装（Windows CNG，零第三方依赖）
// ============================================================
#pragma once
#include <string>

namespace fp {

// 一次性哈希，返回 64 字符大写十六进制；CNG 失败返回空串
std::string Sha256Hex(const std::string& data);

// 一次性哈希，输出原始 32 字节（license 签名用）；失败返回 false
bool Sha256Raw(const std::string& data, unsigned char digest[32]);

}
