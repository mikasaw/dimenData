// ============================================================
// T4 native 通道单测：CPUID 寄存器解析 / 网卡初筛纯函数
// ============================================================
#include "tests/test_util.h"
#include "channels/native_util.h"
#include "channels/native_channel.h"
#include "core/channel_registry.h"
#include "core/field.h"
#include "core/textutil.h"
#include <algorithm>
#include <cstring>

namespace {
constexpr int kAmdLeaf1Eax = 0x11223344;
constexpr int kAmdLeaf1Edx = 0x55667788;
} // namespace

TEST(native_util, cpu_vendor_from_leaf0) {
    // GenuineIntel：EBX="uneG" EDX="Ieni" ECX="letn"
    int ebx = 'u' | ('n' << 8) | ('e' << 16) | ('G' << 24);
    int edx = 'I' | ('e' << 8) | ('n' << 16) | ('i' << 24);
    int ecx = 'l' | ('e' << 8) | ('t' << 16) | ('n' << 24);
    CHECK_STREQ(native_util::CpuVendorFromLeaf0(ebx, edx, ecx), "GenuineIntel");

    // AuthenticAMD（寄存器高字节在前：EBX="Auth" EDX="enti" ECX="AMD\0"）
    int b2 = 'h' | ('t' << 8) | ('u' << 16) | ('A' << 24);
    int d2 = 'i' | ('t' << 8) | ('n' << 16) | ('e' << 24);
    int c2 = 'D' | ('M' << 8) | ('A' << 16) | ('c' << 24);
    CHECK_STREQ(native_util::CpuVendorFromLeaf0(b2, d2, c2), "AuthenticAMD");
}

TEST(native_util, cpu_brand_from_leaves) {
    int leaves[3][4] = {};
    const char* brand = "Example CPU 9000X 8-Core Processor";
    for (int i = 0; i < 48; ++i) {
        const char c = i < (int)std::strlen(brand) ? brand[i] : '\0';
        leaves[i / 16][(i % 16) / 4] |= (int)(unsigned char)c << ((i % 4) * 8);
    }
    CHECK_STREQ(native_util::CpuBrandFromLeaves(leaves), brand);
}

TEST(native_util, cpu_id_format_matches_wmi) {
    // 与 M1 实测一致：EDX=55667788, EAX=11223344 → "5566778811223344"
    CHECK_STREQ(native_util::CpuIdFromLeaf1(kAmdLeaf1Eax, kAmdLeaf1Edx), "5566778811223344");
}

TEST(native_util, nic_physical_filter) {
    using namespace native_util;
    CHECK(NicLikelyPhysical(6, "realtek gaming 2.5gbe family controller"));      // 以太网
    CHECK(NicLikelyPhysical(71, "sample wi-fi 6e 160mhz"));                       // Wi-Fi
    CHECK(!NicLikelyPhysical(24, "software loopback interface 1"));              // 回环
    CHECK(!NicLikelyPhysical(131, "microsoft teredo tunneling adapter"));        // 隧道
    CHECK(!NicLikelyPhysical(6, "vmware virtual ethernet adapter for vmnet1"));
    CHECK(!NicLikelyPhysical(6, "hyper-v virtual ethernet adapter"));
    CHECK(!NicLikelyPhysical(6, "microsoft wi-fi direct virtual adapter"));
    CHECK(!NicLikelyPhysical(6, "microsoft kernel debug network adapter"));
    CHECK(!NicLikelyPhysical(6, "tap-windows adapter v9"));
    CHECK(!NicLikelyPhysical(6, ""));  // 空描述无法判定 → 保守排除
}

TEST(native_util, nvidia_smi_uuid_csv_parse) {
    // 真机实测输出形态（两卡，name 含空格；RTX 4090 的 serial 为 [N/A] 但 uuid 正常）
    const std::string csv =
        "0, NVIDIA GeForce RTX 4090, GPU-01234567-89ab-cdef-0123-456789abcdef\n"
        "1, NVIDIA GeForce RTX 5090, GPU-fedcba98-7654-3210-fedc-ba9876543210\n";
    const auto gpus = native_util::ParseNvidiaSmiUuidCsv(csv);
    CHECK_EQ((int)gpus.size(), 2);
    if (gpus.size() == 2) {
        CHECK_STREQ(gpus[0].index, "0");
        CHECK_STREQ(gpus[0].name, "NVIDIA GeForce RTX 4090");
        CHECK_STREQ(gpus[0].uuid, "GPU-01234567-89ab-cdef-0123-456789abcdef");
        CHECK_STREQ(gpus[1].index, "1");
        CHECK_STREQ(gpus[1].name, "NVIDIA GeForce RTX 5090");
    }
    // name 含逗号（极端情况）：首字段=index、末字段=uuid、中间归 name
    const auto weird = native_util::ParseNvidiaSmiUuidCsv(
        "0, NVIDIA, GeForce RTX 4090, GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    CHECK_EQ((int)weird.size(), 1);
    if (weird.size() == 1) CHECK_STREQ(weird[0].name, "NVIDIA, GeForce RTX 4090");
}

TEST(native_util, nvidia_smi_uuid_csv_malformed) {
    // 空输入 / 空行 / 字段不足 / index 非数字 / uuid 缺占位 → 全部跳过
    CHECK_EQ((int)native_util::ParseNvidiaSmiUuidCsv("").size(), 0);
    CHECK_EQ((int)native_util::ParseNvidiaSmiUuidCsv("\n\n  \n").size(), 0);
    CHECK_EQ((int)native_util::ParseNvidiaSmiUuidCsv("0, RTX 4090\n").size(), 0);
    CHECK_EQ((int)native_util::ParseNvidiaSmiUuidCsv(
                 "X, RTX 4090, GPU-01234567-89ab-cdef-0123-456789abcdef\n").size(), 0);
    CHECK_EQ((int)native_util::ParseNvidiaSmiUuidCsv(
                 "0, RTX 4090, [N/A]\n").size(), 0);
    CHECK_EQ((int)native_util::ParseNvidiaSmiUuidCsv(
                 "0, RTX 4090, N/A\n").size(), 0);
    // CRLF 行尾（真机 nvidia-smi 实际输出）：应正常解析两卡
    CHECK_EQ((int)native_util::ParseNvidiaSmiUuidCsv(
                 "0, NVIDIA GeForce RTX 4090, GPU-01234567-89ab-cdef-0123-456789abcdef\r\n"
                 "1, NVIDIA GeForce RTX 5090, GPU-fedcba98-7654-3210-fedc-ba9876543210\r\n").size(), 2);
    // 无尾换行（最后一行正常解析）
    CHECK_EQ((int)native_util::ParseNvidiaSmiUuidCsv(
                 "0, RTX 4090, GPU-01234567-89ab-cdef-0123-456789abcdef").size(), 1);
}

TEST(native_util, nvidia_gpu_uuid_validation) {
    using native_util::IsNvidiaGpuUuid;
    CHECK(IsNvidiaGpuUuid("GPU-01234567-89ab-cdef-0123-456789abcdef"));
    CHECK(IsNvidiaGpuUuid("GPU-FEDCBA98-7654-3210-FEDC-BA9876543210"));   // 大写
    CHECK(IsNvidiaGpuUuid("MIG-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
    CHECK(!IsNvidiaGpuUuid(""));
    CHECK(!IsNvidiaGpuUuid("[N/A]"));
    CHECK(!IsNvidiaGpuUuid("N/A"));
    CHECK(!IsNvidiaGpuUuid("0"));
    CHECK(!IsNvidiaGpuUuid("GPU-0123456789abcdef0123456789abcdef"));       // 缺连字符
    CHECK(!IsNvidiaGpuUuid("GPU-01234567-89ab-cdef-0123-456789abcde"));    // 末组 11 位
    CHECK(!IsNvidiaGpuUuid("GPU-01234567-89ab-cdef-0123-456789abcdefd"));  // 末组 13 位
    CHECK(!IsNvidiaGpuUuid("GPU-01234567-89ab-cdef-0123-456789abcdeg"));   // 非十六进制
    CHECK(!IsNvidiaGpuUuid("UUID-5219c146-5793-432c-7923-32e229411f2d"));  // 前缀不符
    CHECK(!IsNvidiaGpuUuid("GPU-"));                                       // 仅前缀
}

TEST(native_channel, gpu_uuid_field_declared) {
    // gpu.uuid 已在字段定义表中（参与指纹：gpu 组权重 5）且声明由 native 通道供给
    const FieldDef* def = FindFieldDef(FieldKey::kGpuUuid);
    CHECK(def != nullptr);
    if (def) {
        CHECK_STREQ(def->name, "gpu.uuid");
        CHECK_EQ(def->weight, 5);                    // 参与指纹（gpu 组）
        CHECK(def->group == FpGroup::Gpu);
        CHECK(def->strategy == MergeStrategy::MergeList);
    }
    NativeChannel ch;
    bool declared = false;
    for (auto k : ch.SupportedFields())
        if (k == FieldKey::kGpuUuid) declared = true;
    CHECK(declared);
}

TEST(native_channel, registered_and_supported_fields) {
    // 注册中心含 native；声明字段与 fields.def 键对得上
    const auto& names = ChannelRegistry::Instance().Names();
    CHECK(std::find(names.begin(), names.end(), "native") != names.end());
    NativeChannel ch;
    CHECK(ch.DefaultPriority() == 15);
    CHECK(!ch.SupportedFields().empty());
    for (auto k : ch.SupportedFields())
        CHECK(FindFieldDef(k) != nullptr);
}
