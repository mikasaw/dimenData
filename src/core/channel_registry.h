// ============================================================
// 通道注册中心（开发计划 §3.2 ChannelRegistry）
// 各通道源文件尾 REGISTER_CHANNEL(XxxChannel) 自注册；启动时汇总、
// 按优先级创建实例。预留 LoadChannel(dll) 外置插件入口（二期）。
// ============================================================
#pragma once
#include <memory>
#include <string>
#include <vector>
#include <utility>
#include "core/ichannel.h"

class ChannelRegistry {
public:
    using Factory = std::unique_ptr<IChannel> (*)();

    static ChannelRegistry& Instance();

    // 注册通道工厂（同名重复注册以后者为准）
    void Register(const char* name, Factory f);

    // 按默认优先级升序创建全部已注册通道实例
    std::vector<std::unique_ptr<IChannel>> CreateAll() const;

    // 已注册通道名（按优先级升序），供诊断输出
    std::vector<std::string> Names() const;

    size_t Count() const { return entries_.size(); }

private:
    ChannelRegistry() = default;
    std::vector<std::pair<std::string, Factory>> entries_;  // 注册顺序保持，创建时排序
};

// 自注册宏：放在通道源文件尾（全局作用域），核心代码零改动
#define REGISTER_CHANNEL(CLASS)                                              \
    static bool s_reg_##CLASS = []() {                                       \
        ChannelRegistry::Instance().Register(                                \
            #CLASS, []() -> std::unique_ptr<IChannel> {                      \
                return std::unique_ptr<IChannel>(new CLASS());               \
            });                                                              \
        return true;                                                         \
    }();
