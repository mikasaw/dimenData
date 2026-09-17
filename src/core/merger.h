// ============================================================
// 归并器（开发计划 §3.2）：多通道候选 → 每字段唯一结果
// 四种策略：FirstByPriority（降级链）/ Consensus（标量交叉验证）/
//           MergeList（列表合并去重）/ ConsensusAligned（按 instance_key 逐实例对齐验证）
// 内置：占位符黑名单（矩阵 R3）、cpu.id 跨通道归一化（R1 字节序 + R2 APIC 屏蔽）
// ============================================================
#pragma once
#include <map>
#include <string>
#include <vector>
#include "core/field.h"
#include "core/field_result.h"

// key → 实例列表（按归并后 index 升序）
using MergedResults = std::map<FieldKey, std::vector<FieldResult>>;

// 候选必须按通道优先级升序传入（CollectorManager 保证）；
// 列表字段把各通道全部实例按 (优先级, index) 顺序平铺。
// strategy_override：字段级策略覆盖（配置文件加载属 T8，可为空）。
MergedResults MergeAll(const std::map<FieldKey, std::vector<Candidate>>& by_key,
                       const std::map<FieldKey, MergeStrategy>* strategy_override = nullptr);

// 比较用归一化：默认 trim+小写；kCpuId 做 R1 字节序统一 + R2 清零 APIC 低字节。
// 也用于 MergeList 去重键。
std::string NormalizeForCompare(FieldKey key, const std::string& channel,
                                const std::string& raw);

// 实例对齐键的跨通道归一（ConsensusAligned 配对前调用）：
// 去分隔符（:- 空格.）+ 大写——吸收 wmi "AA:BB:.." 与 native "AABB.." 的
// MAC 形态差异；磁盘 Index 等纯数字键不受影响
std::string NormalizeInstanceKey(const std::string& raw);

// 占位符黑名单（R3）：命中则该候选不参与取值，标记 placeholder
bool IsPlaceholder(const std::string& raw);

// R1：SMBIOS Type4 cpu.id（EAX/EDX 各小端 4 字节的原始 16 hex）
// → "EDX:EAX" 大写 hex（WMI/CPUID 呈现）。非 16 hex 输入原样小写返回。
std::string SmbiosCpuIdToCanonical(const std::string& hex);
