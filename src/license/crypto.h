// ============================================================
// 授权模块 · 签名密钥与 base64（零第三方依赖）
// 算法选型（B1 决策）：Ed25519 不在 CNG 提供范围内，取 RSA-2048 +
// SHA-256 + PKCS#1 v1.5 填充（BCRYPT_PAD_PKCS1）——Windows 10 1809+
// 全系统可用，无外部库。
// 密钥文件 = CNG blob（RSAFULLPRIVATE / RSAPUBLIC）的 base64 文本，
// 可含换行；PEM 互转列为后续任务。
// status 语义：非空时带回失败的 NTSTATUS；返回 false 且 *status==0
// 表示非 CNG 失败（base64 解码失败 / 哈希失败）。
// ============================================================
#pragma once
#include <cstddef>
#include <string>

namespace lic {

// RFC 4648 标准 base64（带 padding）；解码容忍空白字符，遇非法字符返回 false
std::string Base64Encode(const unsigned char* data, size_t len);
bool Base64Decode(const std::string& text, std::string& out);

// 生成 RSA-2048 密钥对（每次调用都是新密钥，~百毫秒级）
bool GenerateKeyPair(std::string& priv_b64, std::string& pub_b64,
                     unsigned long* status = nullptr);

// SHA-256(data) 后 RSA 签名（PKCS#1 v1.5）；返回 base64 签名
bool Sign(const std::string& priv_b64, const std::string& data,
          std::string& sig_b64, unsigned long* status = nullptr);

// 验签；签名/数据/密钥任一不符返回 false
bool Verify(const std::string& pub_b64, const std::string& data,
            const std::string& sig_b64, unsigned long* status = nullptr);

// 密码学随机字节的十六进制串（nonce 用）
bool RandomHex(size_t bytes, std::string& out_hex);

} // namespace lic
