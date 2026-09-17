// ============================================================
// 采集结果模型：单字段结果 + 多通道候选
// 对应开发计划 §3.2：FieldResult{ key, value, source, candidates }
// ============================================================
#pragma once
#include <string>
#include <vector>
#include "core/field.h"

// 单个通道对某字段的一次采集结果
struct Candidate {
    std::string channel;  // 通道名，如 "smbios"
    std::string value;    // 采集值（规范化前的原始值）
    std::string note;     // 诊断信息
    bool        ok;       // 该通道是否取到有效值
    std::string instance_key;  // 实例对齐键（随 FieldResult 透传）
};

// 一个字段经归并后的最终结果
struct FieldResult {
    FieldKey            key = FieldKey::kFieldCount;  // 默认越界哨兵，采集时必然被赋值
    int                 index = 0;      // 列表字段实例序号；标量字段恒为 0
    std::string         instance_key;   // 实例对齐键（如磁盘盘位号），
                                        // ConsensusAligned 按此键跨通道配对；空=不参与对齐
    std::string         value;          // 归并后的最终值；空 = 未取到
    std::string         channel;        // 命中的通道
    std::string         note;           // 诊断/备注
    bool                ok = false;     // 是否取到有效值
    bool                placeholder = false;  // 命中占位符黑名单（矩阵 R3）
    std::string         confidence;     // Consensus 归并时的置信标记：high / fallback
    std::vector<Candidate> candidates;  // 全部通道原始结果（排障 + 交叉验证留痕）
};
