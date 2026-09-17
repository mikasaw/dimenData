#include "core/collector_manager.h"
#include "core/channel_registry.h"
#include "core/thread_pool.h"
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <mutex>

CollectorManager::RunResult CollectorManager::Run(
        const std::map<std::string, ChannelOverride>* channel_override,
        const std::map<FieldKey, MergeStrategy>* strategy_override,
        size_t workers) {
    RunResult rr;
    const auto t0 = std::chrono::steady_clock::now();

    auto channels = ChannelRegistry::Instance().CreateAll();
    if (workers == 0) workers = 4;

    // 应用通道覆盖：禁用剔除、优先级覆盖；按有效优先级稳定排序
    // （覆盖优先级决定降级链顺序与候选装配序）
    std::map<std::string, int> eff_prio;
    std::vector<size_t> keep;
    for (size_t i = 0; i < channels.size(); ++i) {
        auto& ch = channels[i];
        int p = ch->DefaultPriority();
        if (channel_override) {
            auto it = channel_override->find(ch->Name());
            if (it != channel_override->end()) {
                if (!it->second.enabled) {
                    rr.disabled.push_back(ch->Name());
                    continue;
                }
                if (it->second.priority >= 0) p = it->second.priority;
            }
        }
        eff_prio[ch->Name()] = p;
        keep.push_back(i);
    }
    std::stable_sort(keep.begin(), keep.end(), [&](size_t a, size_t b) {
        return eff_prio[channels[a]->Name()] < eff_prio[channels[b]->Name()];
    });

    // 工作线程初始化：MTA 模式注册 COM（已注册时 S_FALSE，幂等）
    ThreadPool pool(workers, [] { CoInitializeEx(nullptr, COINIT_MULTITHREADED); });

    std::mutex mu;
    std::map<FieldKey, std::vector<Candidate>> by_key;

    for (size_t idx : keep) {
        auto& ch = channels[idx];
        // 通道选项下发（须在 Available 懒连接之前）
        if (channel_override) {
            auto it = channel_override->find(ch->Name());
            if (it != channel_override->end())
                for (const auto& o : it->second.options) ch->SetOption(o.first.c_str(), o.second);
        }
        if (!ch->Available()) {
            rr.unavailable.push_back(ch->Name());
            continue;
        }
        const std::string name = ch->Name();
        for (auto key : ch->SupportedFields()) {
            pool.Post([&mu, &by_key, &ch, name, key] {
                auto results = ch->Collect(key);
                std::lock_guard<std::mutex> lk(mu);
                for (auto& r : results) {
                    Candidate c;   // 具名赋值：位置式聚合易错绑（R6 验收 P0 教训）
                    c.channel      = name;
                    c.value        = r.value;
                    c.note         = r.note;
                    c.ok           = r.ok;
                    c.instance_key = r.instance_key;
                    by_key[r.key].push_back(std::move(c));
                }
            });
        }
    }
    pool.WaitIdle();

    // 装配序修正（T6 验收 P1）：任务完成序 ≠ 优先级序。
    // 按有效优先级对每个字段的候选稳定排序，恢复"降级链"前置契约。
    for (auto& kv : by_key)
        std::stable_sort(kv.second.begin(), kv.second.end(),
                         [&eff_prio](const Candidate& a, const Candidate& b) {
                             return eff_prio[a.channel] < eff_prio[b.channel];
                         });

    rr.merged = MergeAll(by_key, strategy_override);
    for (const auto& kv : rr.merged) rr.instances += (int)kv.second.size();
    rr.ms = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - t0).count();
    return rr;
}
