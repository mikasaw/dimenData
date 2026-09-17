// ============================================================
// 注册表通道：OS 标识（MachineGuid/版本）与显示器 EDID
// ============================================================
#pragma once
#include <mutex>
#include <string>
#include <vector>
#include "core/ichannel.h"
#include "channels/registry_parser.h"

class RegistryChannel : public IChannel {
public:
    const char* Name() const override { return "registry"; }
    int DefaultPriority() const override { return 30; }

    bool Available() override;   // 注册表对 HKLM 读取恒可用
    std::vector<FieldKey> SupportedFields() const override;
    std::vector<FieldResult> Collect(FieldKey key) override;

private:
    // 枚举当前注册表中全部 EDID 块并解析（懒加载缓存）
    const std::vector<EdidInfo>& Edids();

    std::vector<EdidInfo> edids_;
    bool edids_loaded_ = false;
    std::mutex mu_;       // 保护懒加载
};
