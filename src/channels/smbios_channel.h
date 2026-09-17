// ============================================================
// SMBIOS 通道（GetSystemFirmwareTable 直读，不依赖 WMI 服务）
// 开发计划 §3.2 通道模块之一；解析逻辑在 smbios_parser（可单测）
// ============================================================
#pragma once
#include <mutex>
#include <string>
#include <vector>
#include "core/ichannel.h"
#include "channels/smbios_parser.h"

class SmbiosChannel : public IChannel {
public:
    const char* Name() const override { return "smbios"; }
    int DefaultPriority() const override { return 10; }

    bool Available() override;
    std::vector<FieldKey> SupportedFields() const override;
    std::vector<FieldResult> Collect(FieldKey key) override;

private:
    // 懒加载：首次 Collect/Available 时读取固件表并解析；失败置 error_ 不抛异常
    bool EnsureParsed();

    SmbiosData  data_;
    std::string error_;    // 读取/解析失败原因
    bool        parsed_ = false;
    std::mutex  mu_;       // 保护懒解析
};

// 单个字段键 → 结果条目（含列表字段的多实例）；供 Collect 与单测共用
std::vector<FieldResult> SmbiosKeyResults(const SmbiosData& d, FieldKey key);
