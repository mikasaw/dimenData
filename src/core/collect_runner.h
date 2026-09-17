// ============================================================
// 采集 + 指纹公共入口：CLI 默认路径与 hwfp.dll 共用
// （配置覆盖 → 线程池并发采集 → 归并 → 加权指纹）
// ============================================================
#pragma once
#include "core/config.h"
#include "core/collector_manager.h"
#include "fingerprint/fingerprint_engine.h"

namespace runner {

// 按配置采集并计算整机指纹；无任何字段产出返回 false
bool CollectFingerprint(const HwfpConfig& cfg,
                        CollectorManager::RunResult& rr,
                        fp::FingerprintOutput& fp_out);

// HwfpConfig → 通道/策略/权重覆盖三元组（collector_manager 形参）
struct Applied {
    std::map<std::string, ChannelOverride> channels;
    std::map<FieldKey, MergeStrategy> strategies;
    std::map<FieldKey, int> weights;
};
Applied ApplyConfig(const HwfpConfig& cfg);

} // namespace runner
