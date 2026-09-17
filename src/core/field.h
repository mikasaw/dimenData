// ============================================================
// 字段模型：FieldKey / FpGroup / MergeStrategy / FieldDef
// 字段清单唯一来源是 core/fields.def（X 宏），本文件负责展开。
// ============================================================
#pragma once
#include <string>

// 指纹分组：一个字段归属于哪个部件子指纹；None = 只采集
enum class FpGroup { None, Sys, Board, Cpu, Disk, Bios, Memory, Os, Nic, Gpu };

// 多通道结果归并策略
enum class MergeStrategy {
    FirstByPriority,  // 取优先级最高且非空的结果（默认降级链）
    Consensus,        // 多通道交叉验证：一致→high confidence；不一致→取高优先级并留 candidates
    MergeList,        // 列表合并去重（memory/nic 等多实例字段）
    ConsensusAligned, // 实例对齐后逐实例交叉验证（磁盘类：按 instance_key=盘位号
                      // 把各通道的同一物理盘配对比较，输出按盘位排序）
};

// 字段键（枚举值 0..kFieldCount-1 与定义表一一对应）
enum class FieldKey {
#define HWFP_FIELD(name, key, group, strategy, weight) k##name,
#include "core/fields.def"
#undef HWFP_FIELD
    kFieldCount  // 越界哨兵：FieldKeyFromName 未命中时返回此值
};

// 字段静态定义
struct FieldDef {
    FieldKey       key;
    const char*    name;      // 字段键字符串，如 "board.serial"
    FpGroup        group;
    MergeStrategy  strategy;  // 默认归并策略（可被配置覆盖）
    int            weight;    // 默认指纹权重（可被配置覆盖；0=只采集）
};

// 定义表（顺序与 fields.def 一致），size = kFieldCount
const FieldDef* GetFieldDefs();
int             GetFieldDefCount();
const FieldDef* FindFieldDef(FieldKey key);          // 越界返回 nullptr
FieldKey        FieldKeyFromName(const char* name);  // 未知名返回 kFieldCount（越界哨兵）
const char*     ToString(FpGroup g);
const char*     ToString(MergeStrategy s);
