#include "core/channel_registry.h"
#include <algorithm>

ChannelRegistry& ChannelRegistry::Instance() {
    static ChannelRegistry inst;
    return inst;
}

void ChannelRegistry::Register(const char* name, Factory f) {
    if (!name || !f) return;
    const std::string n = name;
    for (auto& e : entries_)
        if (e.first == n) { e.second = f; return; }  // 同名覆盖
    entries_.emplace_back(n, f);
}

std::vector<std::unique_ptr<IChannel>> ChannelRegistry::CreateAll() const {
    // 创建实例（工厂返回空指针时跳过，防御性处理），再按 DefaultPriority 稳定排序
    std::vector<std::unique_ptr<IChannel>> tmp;
    tmp.reserve(entries_.size());
    for (const auto& e : entries_) {
        auto inst = e.second();
        if (inst) tmp.push_back(std::move(inst));
    }

    std::stable_sort(tmp.begin(), tmp.end(),
                     [](const std::unique_ptr<IChannel>& a,
                        const std::unique_ptr<IChannel>& b) {
                         return a->DefaultPriority() < b->DefaultPriority();
                     });
    return tmp;
}

std::vector<std::string> ChannelRegistry::Names() const {
    auto insts = CreateAll();
    std::vector<std::string> names;
    names.reserve(insts.size());
    for (const auto& c : insts) names.emplace_back(c->Name());
    return names;
}
