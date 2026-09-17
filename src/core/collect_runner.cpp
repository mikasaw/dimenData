#include "core/collect_runner.h"

namespace runner {

Applied ApplyConfig(const HwfpConfig& cfg) {
    Applied a;
    for (const auto& kv : cfg.channels) {
        ChannelOverride o{kv.second.enabled, kv.second.priority, kv.second.options};
        a.channels[kv.first] = o;
    }
    a.strategies = cfg.field_strategy;
    a.weights = cfg.field_weight;
    return a;
}

bool CollectFingerprint(const HwfpConfig& cfg,
                        CollectorManager::RunResult& rr,
                        fp::FingerprintOutput& fp_out) {
    const Applied applied = ApplyConfig(cfg);
    CollectorManager mgr;
    rr = mgr.Run(applied.channels.empty() ? nullptr : &applied.channels,
                 applied.strategies.empty() ? nullptr : &applied.strategies,
                 cfg.workers);
    if (rr.merged.empty()) return false;
    fp_out = fp::ComputeFingerprint(rr.merged,
                    applied.weights.empty() ? nullptr : &applied.weights);
    return true;
}

} // namespace runner
