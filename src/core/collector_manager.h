// ============================================================
// 采集管理器（开发计划 §3.2 CollectorManager）：
// 注册中心创建通道 → 配置覆盖（启停/优先级）→ Available 过滤 →
// 线程池并发调度 (通道,字段) 任务 → 候选按有效优先级装配 → MergeAll 归并
//
// 并发说明（T6 验收评审确认）：
// - 各通道懒初始化内部已加锁；wmi 的 IWbemServices 代理在 MTA 下可并发
//   ExecQuery（每次查询独立枚举器），连接完成由通道内互斥锁建立 happens-before
// - 硬超时：WMI 半同步枚举不可安全中断，暂以并行化 + join 全等待为主，
//   per_task_timeout_ms 记录在配置中，超时兜底列入 T9 观察项
// ============================================================
#pragma once
#include <map>
#include <string>
#include <vector>
#include "core/merger.h"

// 通道覆盖：enabled=false 剔除；priority>=0 覆盖默认优先级；
// options 经 IChannel::SetOption 下发（如 wmi 的 tpm_probe）
struct ChannelOverride {
    bool enabled = true;
    int  priority = -1;
    std::map<std::string, int> options;
};

class CollectorManager {
public:
    struct RunResult {
        MergedResults merged;                 // 归并后的字段结果
        std::vector<std::string> unavailable; // Available()=false 被剔除的通道
        std::vector<std::string> disabled;    // 配置禁用的通道
        int    instances = 0;                 // 归并后字段实例总数
        double ms = 0;                        // 总耗时
    };

    // workers=0 → 自动（4）；通道/策略覆盖可空
    RunResult Run(const std::map<std::string, ChannelOverride>* channel_override = nullptr,
                  const std::map<FieldKey, MergeStrategy>* strategy_override = nullptr,
                  size_t workers = 0);
};
