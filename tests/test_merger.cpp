// ============================================================
// T6 归并器单测：三策略 / 占位符黑名单（R3）/ cpu.id 跨通道归一（R1/R2）
// 部分用例数据取自 M1 真机实测值（见 docs/M1-POC-采集项可用性矩阵.md）
// ============================================================
#include "tests/test_util.h"
#include "core/merger.h"
#include <map>

namespace {

Candidate Cand(const char* channel, const char* value, bool ok = true) {
    return Candidate{ channel, value, "", ok };
}

// 带实例对齐键的候选（ConsensusAligned 用）
Candidate CandKeyed(const char* channel, const char* value, const char* key) {
    Candidate c{ channel, value, "", true };
    c.instance_key = key;
    return c;
}

// 便捷构造单字段输入
std::map<FieldKey, std::vector<Candidate>> One(FieldKey k, std::vector<Candidate> cs) {
    std::map<FieldKey, std::vector<Candidate>> m;
    m[k] = std::move(cs);
    return m;
}

} // namespace

TEST(merger, first_by_priority_and_placeholder_blacklist) {
    // R3：最高优先级通道给占位值 → 跳过取下一通道
    auto m = One(FieldKey::kSysSerial,
                 { Cand("smbios", "To be filled by O.E.M."),
                   Cand("wmi", "PF1ABC7") });
    auto r = MergeAll(m);
    CHECK_EQ((int)r[FieldKey::kSysSerial].size(), 1);
    CHECK_STREQ(r[FieldKey::kSysSerial][0].value, "PF1ABC7");
    CHECK_STREQ(r[FieldKey::kSysSerial][0].channel, "wmi");
    CHECK(!r[FieldKey::kSysSerial][0].placeholder);

    // 全占位 → ok=false + placeholder 标记
    auto m2 = One(FieldKey::kSysSerial,
                  { Cand("smbios", "None"), Cand("wmi", "unknown") });
    auto r2 = MergeAll(m2);
    CHECK_EQ((int)r2[FieldKey::kSysSerial].size(), 1);
    CHECK(!r2[FieldKey::kSysSerial][0].ok);
    CHECK(r2[FieldKey::kSysSerial][0].placeholder);

    // 大小写不敏感
    auto m3 = One(FieldKey::kSysSerial, { Cand("smbios", "  DEFAULT STRING  ") });
    auto r3 = MergeAll(m3);
    CHECK(r3[FieldKey::kSysSerial][0].placeholder);
}

TEST(merger, consensus_agree_high_confidence) {
    // M1 真机：board.serial smbios 与 wmi 一致 → high
    auto m = One(FieldKey::kBoardSerial,
                 { Cand("smbios", "SYNTH_0000_BOARD_0001"),
                   Cand("wmi", "SYNTH_0000_BOARD_0001") });
    auto r = MergeAll(m);
    CHECK_STREQ(r[FieldKey::kBoardSerial][0].confidence, "high");
    CHECK_STREQ(r[FieldKey::kBoardSerial][0].channel, "smbios");
}

TEST(merger, consensus_cpu_id_r1_r2_cross_channel) {
    // M1 真机实测：SMBIOS 与 CPUID/WMI 呈现互为字节序（R1），
    // 且 R2 屏蔽 EAX 低字节后应判定一致
    auto m = One(FieldKey::kCpuId,
                 { Cand("smbios", "4433221188776655"),
                   Cand("native", "5566778811223344") });
    auto r = MergeAll(m);
    CHECK_STREQ(r[FieldKey::kCpuId][0].confidence, "high");
    // 保留命中通道的原始文本（smbios 侧）
    CHECK_STREQ(r[FieldKey::kCpuId][0].value, "4433221188776655");

    // 归一化函数直测：两格式归一后相等；APIC 字节被清零
    const std::string a = NormalizeForCompare(FieldKey::kCpuId, "smbios", "4433221188776655");
    const std::string b = NormalizeForCompare(FieldKey::kCpuId, "native", "5566778811223344");
    CHECK_STREQ(a, b);
    CHECK_STREQ(b, "5566778811223300");

    // R2 反例：EAX 高位不同（不同微架构）不应判一致
    const std::string c = NormalizeForCompare(FieldKey::kCpuId, "native", "556677881122AA44");
    CHECK(a != c);
}

TEST(merger, consensus_disagreement_fallback) {
    // disk.serial 已改为 MergeList（多实例），分歧回退用策略覆盖驱动 Consensus
    std::map<FieldKey, MergeStrategy> ov;
    ov[FieldKey::kDiskSerial] = MergeStrategy::Consensus;
    auto m = One(FieldKey::kDiskSerial,
                 { Cand("native", "SYNTHHDD000000000001"),
                   Cand("wmi", "COMPLETELY-DIFFERENT") });
    auto r = MergeAll(m, &ov);
    CHECK_STREQ(r[FieldKey::kDiskSerial][0].confidence, "fallback");
    CHECK_STREQ(r[FieldKey::kDiskSerial][0].value, "SYNTHHDD000000000001");
}

TEST(merger, merge_list_dedup_and_reindex) {
    // M1 真机形态：native 2 块物理网卡；wmi PhysicalAdapter=TRUE 混入
    // VMware VMnet 且与 native 重叠 → 合并去重后 4 条，index 连续
    // （nic.* 默认策略已改 ConsensusAligned，此处用覆盖锁 MergeList 语义）
    std::map<FieldKey, MergeStrategy> ov;
    ov[FieldKey::kNicMac] = MergeStrategy::MergeList;
    auto m = One(FieldKey::kNicMac,
                 { Cand("native", "AABBCCDDEE01"),
                   Cand("native", "AABBCCDDEE02"),
                   Cand("wmi", "AABBCCDDEE03"),
                   Cand("wmi", "AABBCCDDEE04"),
                   Cand("wmi", "AABBCCDDEE01"),      // 重复（跨通道）
                   Cand("wmi", "aabbccddee02") });   // 重复（大小写差异）
    auto r = MergeAll(m, &ov);
    const auto& v = r[FieldKey::kNicMac];
    CHECK_EQ((int)v.size(), 4);
    if (v.size() == 4) {
        CHECK_STREQ(v[0].value, "AABBCCDDEE01");
        CHECK_STREQ(v[1].value, "AABBCCDDEE02");
        CHECK_STREQ(v[2].value, "AABBCCDDEE03");
        CHECK_STREQ(v[3].value, "AABBCCDDEE04");
        CHECK_EQ(v[0].index, 0);
        CHECK_EQ(v[3].index, 3);
    }
}

TEST(merger, nic_consensus_aligned_by_mac) {
    // T12：nic.* 按 MAC 实例对齐——wmi 冒号/连字符分隔形态与 native 连续 hex
    // 在组键上归一后配对；值取最高优先级通道（native），配对组 confidence=high
    auto m = One(FieldKey::kNicMac,
                 { CandKeyed("native", "AABBCCDDEE01", "AABBCCDDEE01"),
                   CandKeyed("native", "AABBCCDDEE02", "AABBCCDDEE02"),
                   CandKeyed("wmi", "aabbccddee01", "AA:BB:CC:DD:EE:01") });  // 同卡异形态
    auto r = MergeAll(m);
    const auto& mac = r[FieldKey::kNicMac];
    CHECK_EQ((int)mac.size(), 2);
    if (mac.size() == 2) {
        CHECK_STREQ(mac[0].value, "AABBCCDDEE01");     // native 优先
        CHECK_STREQ(mac[0].channel, "native");
        CHECK_STREQ(mac[0].confidence, "high");        // 跨通道配对一致
        CHECK_STREQ(mac[0].instance_key, "AABBCCDDEE01");
        CHECK_STREQ(mac[1].value, "AABBCCDDEE02");
        CHECK_STREQ(mac[1].confidence, "single");      // 仅单通道
    }

    // name 与 mac 同键对齐：同一物理网卡的双通道名称不同（native"以太网" vs
    // wmi"Realtek..."）→ 组内投票分歧 = fallback（取高优先级 native，单条输出）
    auto n = One(FieldKey::kNicName,
                 { CandKeyed("native", "Ethernet", "aabbccddee01"),
                   CandKeyed("wmi", "Realtek Gaming 2.5GbE", "AA-BB-CC-DD-EE-01"),
                   CandKeyed("wmi", "Wi-Fi", "AABBCCDDEE02") });
    auto rn = MergeAll(n);
    const auto& name = rn[FieldKey::kNicName];
    CHECK_EQ((int)name.size(), 2);
    if (name.size() == 2) {
        CHECK_STREQ(name[0].value, "Ethernet");
        CHECK_STREQ(name[0].confidence, "fallback");   // 配对但名称分歧
        CHECK_STREQ(name[1].value, "Wi-Fi");
        CHECK_STREQ(name[1].confidence, "single");     // 仅单通道
        CHECK_EQ(name[1].index, 1);
    }

    // 无键候选独立成组，排在有键组之后
    auto u = One(FieldKey::kNicMac,
                 { CandKeyed("wmi", "AABBCCDDEE09", "AA:BB:CC:DD:EE:09"),
                   Cand("native", "AABBCCDDEE0A") });   // 无键
    auto ru = MergeAll(u);
    const auto& um = ru[FieldKey::kNicMac];
    CHECK_EQ((int)um.size(), 2);
    if (um.size() == 2) {
        CHECK_STREQ(um[0].value, "AABBCCDDEE09");      // 有键在前
        CHECK_STREQ(um[1].value, "AABBCCDDEE0A");      // 无键在后
    }
}

TEST(merger, consensus_tie_break_by_rank) {
    // T6 复审用例：{2,2} 并列时取含 rank0 候选的组，而非字典序靠前的组
    std::map<FieldKey, MergeStrategy> ov;
    ov[FieldKey::kSysSerial] = MergeStrategy::Consensus;
    auto m = One(FieldKey::kSysSerial,
                 { Cand("native", "ZZZ-1"),     // rank0 → ZZZ 组
                   Cand("wmi", "AAA-2"),
                   Cand("smbios", "ZZZ-1"),
                   Cand("registry", "AAA-2") });
    auto r = MergeAll(m, &ov);
    CHECK_STREQ(r[FieldKey::kSysSerial][0].confidence, "high");
    CHECK_STREQ(r[FieldKey::kSysSerial][0].value, "ZZZ-1");
    CHECK_STREQ(r[FieldKey::kSysSerial][0].channel, "native");
}

TEST(merger, merge_list_multiplicity_preserved) {
    // 多重重集语义：跨通道去重但保留实例数（2×16G 双内存条，矩阵 R8）
    auto m = One(FieldKey::kMemorySize,
                 { Cand("smbios", "16384"), Cand("smbios", "16384"),
                   Cand("wmi", "16384"),    Cand("wmi", "16384") });
    auto r = MergeAll(m);
    CHECK_EQ((int)r[FieldKey::kMemorySize].size(), 2);
    CHECK_STREQ(r[FieldKey::kMemorySize][0].value, "16384");
    CHECK_STREQ(r[FieldKey::kMemorySize][1].value, "16384");
    CHECK_EQ(r[FieldKey::kMemorySize][0].index, 0);
    CHECK_EQ(r[FieldKey::kMemorySize][1].index, 1);
}

namespace {
Candidate WithNote(const char* channel, const char* value, bool ok, const char* note) {
    Candidate c = Cand(channel, value, ok);
    c.note = note;
    return c;
}
} // namespace

TEST(merger, failure_note_from_channel_preserved) {
    // 降级条目保留通道给出的原因（如 "nvidia-smi 未找到"），而非笼统"无有效候选"
    auto m = One(FieldKey::kGpuUuid,
                 { WithNote("native", "", false,
                            "nvidia-smi 未找到（非 NVIDIA 平台或无 NVIDIA 驱动）") });
    auto r = MergeAll(m);
    const auto& v = r[FieldKey::kGpuUuid];
    CHECK_EQ((int)v.size(), 1);
    if (v.size() == 1) {
        CHECK(!v[0].ok);
        CHECK(!v[0].placeholder);
        CHECK_STREQ(v[0].note,
                    "nvidia-smi 未找到（非 NVIDIA 平台或无 NVIDIA 驱动）");
    }
}

TEST(merger, failure_is_not_placeholder) {
    // 全失败（ok=false）≠ 占位符：仅黑名单命中才标 placeholder
    auto m = One(FieldKey::kOsSecureBoot, { Cand("registry", "", false) });
    auto r = MergeAll(m);
    CHECK(!r[FieldKey::kOsSecureBoot][0].placeholder);
    CHECK_STREQ(r[FieldKey::kOsSecureBoot][0].note, "无有效候选");
}

namespace {
// 带盘位键的候选（逐盘对齐用）
Candidate Keyed(const char* channel, const char* value, const char* ikey) {
    Candidate c;
    c.channel = channel;
    c.value = value;
    c.ok = true;
    c.instance_key = ikey;
    return c;
}
} // namespace

TEST(merger, consensus_aligned_tie_and_unkeyed_order) {
    // 并列裁决（验收 P2）：同盘位 4 候选 2:2 并列，应取含最高优先级（rank0）的组，
    // 而非字典序靠前的组——此断言对"去掉 rank 裁决"的突变可判别
    auto m = One(FieldKey::kDiskSerial,
                 { Keyed("native",   "ZZZ", "5"),
                   Keyed("wmi",      "AAA", "5"),
                   Keyed("smbios",   "ZZZ", "5"),
                   Keyed("registry", "AAA", "5") });
    auto r = MergeAll(m);
    const auto& v = r[FieldKey::kDiskSerial];
    CHECK_EQ((int)v.size(), 1);
    if (v.size() == 1) {
        CHECK_STREQ(v[0].value, "ZZZ");            // rank0 所在组胜出
        CHECK_STREQ(v[0].confidence, "high");
    }

    // 无键候选排序（验收 P1）：显式排在有键组之后，按生成序（不受字典序影响）
    auto m2 = One(FieldKey::kDiskSerial,
                  { Keyed("wmi", "KEY-TEN", "10"),
                    Cand("registry", "NO-KEY-A"),
                    Keyed("native", "KEY-ZERO", "0"),
                    Cand("registry", "NO-KEY-B") });
    auto r2 = MergeAll(m2);
    const auto& v2 = r2[FieldKey::kDiskSerial];
    CHECK_EQ((int)v2.size(), 4);
    if (v2.size() == 4) {
        CHECK_STREQ(v2[0].value, "KEY-ZERO");      // 有键组在前（数值序）
        CHECK_STREQ(v2[1].value, "KEY-TEN");
        CHECK_STREQ(v2[2].value, "NO-KEY-A");      // 无键组按生成序排后
        CHECK_STREQ(v2[3].value, "NO-KEY-B");
    }
}

TEST(merger, consensus_aligned_instance_key_retained) {
    // 归并结果保留盘位键（验收 P2）：盘位稀疏时下游仍可追溯物理盘号
    auto m = One(FieldKey::kDiskSerial, { Keyed("native", "SER-3", "3") });
    auto r = MergeAll(m);
    const auto& v = r[FieldKey::kDiskSerial];
    CHECK_EQ((int)v.size(), 1);
    if (v.size() == 1) {
        CHECK_STREQ(v[0].instance_key, "3");
        CHECK_EQ(v[0].index, 0);                   // index 仍为输出位置
    }
}

TEST(merger, consensus_aligned_per_disk) {
    // 逐盘对齐（R5 目标）：native 与 wmi 的同一盘位配对比较，不同盘位不互相污染
    auto m = One(FieldKey::kDiskSerial,
                 { Keyed("native", "SYNTHHDD000000000001", "0"),
                   Keyed("native", "0011223344556677", "1"),
                   Keyed("wmi",    "SYNTHHDD000000000001", "0"),
                   Keyed("wmi",    "0011223344556677", "1") });
    auto r = MergeAll(m);
    const auto& v = r[FieldKey::kDiskSerial];
    CHECK_EQ((int)v.size(), 2);
    if (v.size() == 2) {
        CHECK_STREQ(v[0].value, "SYNTHHDD000000000001");
        CHECK_STREQ(v[0].confidence, "high");      // 盘位 0 两通道一致
        CHECK_EQ(v[0].index, 0);
        CHECK_STREQ(v[1].confidence, "high");      // 盘位 1 一致
        CHECK_EQ(v[1].index, 1);
    }
}

TEST(merger, consensus_aligned_ordering_and_disagreement) {
    // 排序：盘位键数值序（"0","2","10"），非通道返回顺序
    // 分歧：同盘位两通道不同 → fallback 取最高优先级（native）
    // 单通道盘位：仍然输出（single），不因缺另一通道而丢失
    auto m = One(FieldKey::kDiskSerial,
                 { Keyed("wmi",    "DISK-TEN",  "10"),
                   Keyed("native", "DISK-ZERO", "0"),
                   Keyed("native", "DISK-TWO",  "2"),
                   Keyed("wmi",    "OTHER-TWO", "2") });
    auto r = MergeAll(m);
    const auto& v = r[FieldKey::kDiskSerial];
    CHECK_EQ((int)v.size(), 3);
    if (v.size() == 3) {
        CHECK_STREQ(v[0].value, "DISK-ZERO");      // 盘位 0
        CHECK_STREQ(v[0].confidence, "single");
        CHECK_STREQ(v[1].value, "DISK-TWO");       // 盘位 2 分歧 → native 优先
        CHECK_STREQ(v[1].confidence, "fallback");
        CHECK_STREQ(v[2].value, "DISK-TEN");       // 盘位 10 排在 2 之后（数值序）
        CHECK_EQ(v[2].index, 2);
    }
}

TEST(merger, consensus_aligned_r4_normalization) {
    // R4 比较口径：NVMe 序列号分隔符差异不构成"分歧"
    auto m = One(FieldKey::kDiskSerial,
                 { Keyed("native", "A1B2_C3D4_E5F6_0007.", "2"),
                   Keyed("wmi",    "A1B2C3D4E5F60007",    "2") });
    auto r = MergeAll(m);
    const auto& v = r[FieldKey::kDiskSerial];
    CHECK_EQ((int)v.size(), 1);
    if (v.size() == 1) {
        CHECK_STREQ(v[0].confidence, "high");      // 归一化后一致
        CHECK_STREQ(v[0].value, "A1B2_C3D4_E5F6_0007.");   // 保留原始格式
    }
}

TEST(merger, strategy_override_and_empty_input) {
    // 策略覆盖：sys.serial 默认 First，可覆盖为 Consensus
    std::map<FieldKey, MergeStrategy> ov;
    ov[FieldKey::kSysSerial] = MergeStrategy::Consensus;
    auto m = One(FieldKey::kSysSerial,
                 { Cand("smbios", "SER-A"), Cand("wmi", "SER-A") });
    auto r = MergeAll(m, &ov);
    CHECK_STREQ(r[FieldKey::kSysSerial][0].confidence, "high");

    // 空候选输入不崩溃
    auto r2 = MergeAll(One(FieldKey::kCpuId, { Cand("native", "", false) }));
    CHECK(!r2[FieldKey::kCpuId][0].ok);
}
