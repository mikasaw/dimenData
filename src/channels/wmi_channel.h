// ============================================================
// WMI 通道（COM / IWbemLocator，ROOT\CIMV2 表驱动查询）
// COM 生命周期：进程级一次性初始化（MTA），通道销毁不反初始化——
// 本进程是唯一 COM 用户，进程退出由系统回收（避免与其他组件竞争安全设置）
//
// 性能设计（T9）：按 WQL（类）批量查询一次并缓存"属性→值"行，
// 同类的多个字段共享缓存——避免同类逐字段重复查询（Win32_Processor
// 单类查询在本机即 ~1.1s）；不同类并发执行。
// ============================================================
#pragma once
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include "core/ichannel.h"

class WmiChannel : public IChannel {
public:
    WmiChannel() = default;
    ~WmiChannel() override;

    const char* Name() const override { return "wmi"; }
    int DefaultPriority() const override { return 20; }
    void SetOption(const char* key, int value) override;

    bool Available() override;   // 懒初始化 COM 并连接 ROOT\CIMV2
    std::vector<FieldKey> SupportedFields() const override;
    std::vector<FieldResult> Collect(FieldKey key) override;

private:
    // 连接服务（cimv2 或 tpm 命名空间）；失败置 last_error_
    bool EnsureConnected();
    // 构造失败结果（不抛异常契约）
    std::vector<FieldResult> Fail(FieldKey key) const;

    // 按类缓存：一条 WQL 的全部行（每行 = 属性名 → 值）
    struct ClassCache {
        bool done = false;
        bool ok = false;
        std::string error;
        std::vector<std::map<std::string, std::string>> rows;
        std::mutex mu;                    // 同类查询互斥（异类并发）
    };

    // 确保该 WQL 已查询完成；svc 由调用方按命名空间给出
    const ClassCache& EnsureClass(const std::wstring& wql, void* svc);
    // 预热：顺序执行全部类查询（实测并发查询在 WMI 服务端互相踩踏，
    // 顺序执行全部类查询仅 ~170ms，故在 Available 阶段一次完成）
    void WarmCache();

    bool  init_done_ = false;    // CoInitializeEx/Security 已执行
    bool  connected_ = false;
    void* locator_   = nullptr;  // IWbemLocator*（避免在头文件引 COM 头）
    void* svc_       = nullptr;  // IWbemServices*(ROOT\CIMV2)
    void* tpm_svc_   = nullptr;  // IWbemServices*(Security\MicrosoftTpm)，可选
    std::string last_error_;
    bool tpm_probe_ = false;              // 默认不连 MicrosoftTpm 命名空间（可能阻塞数秒）
    std::mutex mu_;                       // 保护懒连接与状态位
    std::mutex cache_map_mu_;             // 保护 class_cache_ 的 map 结构
    std::map<std::wstring, ClassCache> class_cache_;
};

namespace wmi_channel_test {
// 规格表防回归统计（R6 验收 P0 教训：位置式初始化错绑曾静默过滤字段）
int NicFilterSpecCountForTest();   // 应恰为网卡 2 条
int GpuFilterSpecCountForTest();   // 应恰为显卡 2 条
int KeyedSpecCountForTest();       // 应恰为磁盘 4 条（Index 对齐键）
}
