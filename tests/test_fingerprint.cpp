// ============================================================
// T7 指纹引擎单测：规范化（R1/R2/R4/日期）、确定性、组隔离、相似度
// ============================================================
#include "tests/test_util.h"
#include "fingerprint/fingerprint_engine.h"
#include "fingerprint/sha256.h"

TEST(fingerprint_sha256, known_vector) {
    // 与 M1 POC/native 通道自检同源："abc" 的 SHA-256
    CHECK_STREQ(fp::Sha256Hex("abc"),
                "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
    CHECK_STREQ(fp::Sha256Hex(""), 
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
}

TEST(fingerprint_normalize, cpu_id_r1_r2) {
    // R1：smbios 来源转 canonical；R2：APIC 低字节清零；大小写统一
    CHECK_STREQ(fp::NormalizeValueForFingerprint(FieldKey::kCpuId, "smbios",
                                                 "4433221188776655"),
                "5566778811223300");
    CHECK_STREQ(fp::NormalizeValueForFingerprint(FieldKey::kCpuId, "wmi",
                                                 "5566778811223344"),
                "5566778811223300");
    // 不同微架构（EAX 高位不同）不收敛
    CHECK(fp::NormalizeValueForFingerprint(FieldKey::kCpuId, "wmi", "556677881122AA44") !=
          fp::NormalizeValueForFingerprint(FieldKey::kCpuId, "wmi", "5566778811223344"));
}

TEST(fingerprint_normalize, disk_serial_r4) {
    // M1 实测 NVMe 原始格式含下划线与尾点 → 归一化后可与同值异格式合并
    CHECK_STREQ(fp::NormalizeValueForFingerprint(FieldKey::kDiskSerial, "wmi",
                                                 "A1B2_C3D4_E5F6_0007."),
                "A1B2C3D4E5F60007");
    CHECK_STREQ(fp::NormalizeValueForFingerprint(FieldKey::kDiskSerial, "native",
                                                 "synthhdd000000000001"),
                "SYNTHHDD000000000001");
}

TEST(fingerprint_normalize, disk_serial_sata_r4_cross_channel) {
    // R4 对照结论（2026-09-17，宿主机三块盘实测）：现代 Windows 存储栈下
    // StorageDeviceProperty 与 WMI 的 SATA 序列号无字节序差异。本用例锁定
    // 规范化层行为（空格/分隔符吸收 + 通道标签对称）；采集层字节序回归
    // 需真机对照覆盖。
    const char* kSataSample = "0011223344556677";   // SATA 样例值，native 与 wmi 一致
    CHECK_STREQ(fp::NormalizeValueForFingerprint(FieldKey::kDiskSerial, "native",
                                                 kSataSample),
                fp::NormalizeValueForFingerprint(FieldKey::kDiskSerial, "wmi",
                                                 kSataSample));
    // ATA 常见的空格填充与分隔符差异被 R4 规范化吸收
    CHECK_STREQ(fp::NormalizeValueForFingerprint(FieldKey::kDiskSerial, "native",
                                                 "  0011223344556677  "),
                fp::NormalizeValueForFingerprint(FieldKey::kDiskSerial, "wmi",
                                                 kSataSample));
}

TEST(fingerprint_normalize, bios_release_date) {
    // smbios "MM/DD/YYYY" → ISO；wmi 通道层已转 ISO 原样通过
    CHECK_STREQ(fp::NormalizeValueForFingerprint(FieldKey::kBiosReleaseDate, "smbios",
                                                 "07/25/2024"),
                "2024-07-25");
    CHECK_STREQ(fp::NormalizeValueForFingerprint(FieldKey::kBiosReleaseDate, "wmi",
                                                 "2024-07-25"),
                "2024-07-25");
}

namespace {

// 构造合并结果条目
FieldResult FR(FieldKey k, const char* channel, const char* value, bool ok = true) {
    FieldResult r;
    r.key = k;
    r.channel = channel;
    r.value = value;
    r.ok = ok;
    return r;
}

} // namespace

TEST(fingerprint_engine, deterministic_and_group_isolation) {
    MergedResults m;
    m[FieldKey::kBoardSerial]  = { FR(FieldKey::kBoardSerial, "smbios", "BRD-1") };
    m[FieldKey::kSysSerial]    = { FR(FieldKey::kSysSerial, "wmi", "SYS-9") };
    m[FieldKey::kCpuId]        = { FR(FieldKey::kCpuId, "native", "5566778811223344") };
    m[FieldKey::kBiosVendor]   = { FR(FieldKey::kBiosVendor, "smbios", "AMI") };
    m[FieldKey::kGpuName]      = { FR(FieldKey::kGpuName, "wmi", "RTX 4090") };  // 权重0不入

    auto a = fp::ComputeFingerprint(m);
    auto b = fp::ComputeFingerprint(m);
    CHECK_STREQ(a.master, b.master);                 // 确定性
    CHECK(!a.master.empty());
    CHECK(!a.sub.count("none"));                     // 权重0组不产生子指纹

    // 换盘（disk 组变化）→ master 变，board 子指纹不变、disk 子指纹变
    MergedResults m2 = m;
    m2[FieldKey::kDiskSerial] = { FR(FieldKey::kDiskSerial, "native", "DISK-A") };
    auto c = fp::ComputeFingerprint(m2);
    CHECK(a.master != c.master);
    CHECK_STREQ(a.sub.at("board"), c.sub.at("board"));
    CHECK(a.sub.count("disk") == 0 || a.sub.at("disk") != c.sub.at("disk"));

    // 实例顺序不影响指纹（列表字段排序后入哈希）
    MergedResults m3 = m;
    m3[FieldKey::kDiskSerial] = { FR(FieldKey::kDiskSerial, "native", "DISK-A"),
                                  FR(FieldKey::kDiskSerial, "native", "DISK-B") };
    MergedResults m4 = m;
    m4[FieldKey::kDiskSerial] = { FR(FieldKey::kDiskSerial, "native", "DISK-B"),
                                  FR(FieldKey::kDiskSerial, "native", "DISK-A") };
    auto d3 = fp::ComputeFingerprint(m3);
    auto d4 = fp::ComputeFingerprint(m4);
    CHECK_STREQ(d3.master, d4.master);

    // 缺失字段=整行跳过：m 无 disk.serial，disk 组不存在
    CHECK(!a.sub.count("disk"));
}

TEST(fingerprint_engine, gpu_group_participates) {
    MergedResults m;
    m[FieldKey::kBoardSerial] = { FR(FieldKey::kBoardSerial, "smbios", "BRD-1") };
    m[FieldKey::kGpuUuid]     = { FR(FieldKey::kGpuUuid, "native",
                                     "GPU-01234567-89ab-cdef-0123-456789abcdef") };
    auto a = fp::ComputeFingerprint(m);
    CHECK(a.sub.count("gpu") == 1);                     // gpu 独立子指纹组
    CHECK(a.contributors.size() == 2);                  // gpu.uuid 参与整机哈希
    bool hasGpuLine = false;
    for (const auto& c : a.contributors)
        if (c.find("gpu.uuid=") == 0) hasGpuLine = true;
    CHECK(hasGpuLine);

    // 换显卡（UUID 变）→ 整机与 gpu 子指纹均变，board 子指纹不变
    MergedResults m2 = m;
    m2[FieldKey::kGpuUuid] = { FR(FieldKey::kGpuUuid, "native",
                                  "GPU-00000000-0000-0000-0000-000000000000") };
    auto b = fp::ComputeFingerprint(m2);
    CHECK(a.master != b.master);
    // count() 守卫后再取值：缺失即断言语义失败，不让 .at() 抛异常中止整个测试进程
    CHECK(a.sub.count("gpu") == 1);
    if (a.sub.count("gpu") == 1 && b.sub.count("gpu") == 1)
        CHECK(a.sub.count("gpu") && a.sub.at("gpu") != b.sub.at("gpu"));
    CHECK(a.sub.count("board") == 1 && b.sub.count("board") == 1);
    if (a.sub.count("board") == 1 && b.sub.count("board") == 1)
        CHECK_STREQ(a.sub.at("board"), b.sub.at("board"));
    // 仅 gpu 组漂移：相似度 = board30 / (board30 + gpu5) ≈ 0.857（组权重比值）
    const double sim_swap = fp::Similarity(a, b);
    CHECK(sim_swap > 0.8 && sim_swap < 0.9);

    // 无 NVIDIA（无 gpu.uuid）→ 不产生 gpu 组，指纹照常（AMD/Intel 平台）
    MergedResults m3;
    m3[FieldKey::kBoardSerial] = { FR(FieldKey::kBoardSerial, "smbios", "BRD-1") };
    auto c = fp::ComputeFingerprint(m3);
    CHECK(c.sub.count("gpu") == 0);
    CHECK(!c.master.empty());

    // 权重覆盖为 0 可退出指纹（配置化回退路径）
    std::map<FieldKey, int> zero;
    zero[FieldKey::kGpuUuid] = 0;
    auto d = fp::ComputeFingerprint(m, &zero);
    CHECK(d.sub.count("gpu") == 0);
    CHECK_STREQ(d.master, c.master);                    // 等价于无 gpu.uuid 的机器
}

TEST(fingerprint_engine, weight_override_and_similarity) {
    MergedResults m;
    m[FieldKey::kBoardSerial] = { FR(FieldKey::kBoardSerial, "smbios", "BRD-1") };
    m[FieldKey::kSysSerial]   = { FR(FieldKey::kSysSerial, "wmi", "SYS-9") };

    // 权重覆盖为 0：字段退出指纹
    std::map<FieldKey, int> zero;
    zero[FieldKey::kSysSerial] = 0;
    auto a = fp::ComputeFingerprint(m);
    auto b = fp::ComputeFingerprint(m, &zero);
    CHECK(a.master != b.master);
    bool sysFound = false;
    for (const auto& c : b.contributors)
        if (c.find("sys.serial=") == 0) sysFound = true;
    CHECK(!sysFound);

    // 相似度：同一对象 = 1；仅 sys 组漂移 → 扣除 sys 组权重占比
    MergedResults m2 = m;
    m2[FieldKey::kSysSerial] = { FR(FieldKey::kSysSerial, "wmi", "CHANGED") };
    auto c = fp::ComputeFingerprint(m2);
    CHECK(fp::Similarity(a, a) == 1.0);
    const double s = fp::Similarity(a, c);
    CHECK(s > 0.0 && s < 1.0);
    // sys 组权重 30+15+5=50；非 sys 组合计 110（board30+cpu30+disk25+bios15+mem10+nic5+gpu 无）
    CHECK(s < 0.9);   // sys 占比大，漂移后相似度明显低于 1
}
