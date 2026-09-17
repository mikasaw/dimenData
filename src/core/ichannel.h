// ============================================================
// 采集通道统一接口（开发计划 §3.2 IChannel）
// 每种采集"手段"实现本接口，并在源文件尾用 REGISTER_CHANNEL 自注册。
// ============================================================
#pragma once
#include <vector>
#include "core/field_result.h"

class IChannel {
public:
    virtual ~IChannel() = default;

    // 通道名（小写，稳定，写入输出与配置）：如 "smbios" / "wmi"
    virtual const char* Name() const = 0;

    // 默认优先级，数值越小越优先；可被配置覆盖
    virtual int DefaultPriority() const = 0;

    // 运行时探测（WMI 服务是否可用、SMBIOS 表是否存在等）；
    // 不可用的通道在调度前被整体剔除
    virtual bool Available() = 0;

    // 本通道声明可采集的字段集合
    virtual std::vector<FieldKey> SupportedFields() const = 0;

    // 通道可选参数（配置下发，默认忽略）。key 语义由具体通道定义，
    // 如 wmi 通道的 "tpm_probe"（0/1：是否连接 MicrosoftTpm 命名空间）
    virtual void SetOption(const char* key, int value) { (void)key; (void)value; }

    // 采集一个字段的全部实例：
    //   标量字段返回 1 个元素（index=0）；列表字段返回 N 个元素（index=0..N-1）。
    // 失败不抛异常：返回 ok=false 的条目或空表，原因写 note。
    virtual std::vector<FieldResult> Collect(FieldKey key) = 0;
};
