#include "core/field.h"

namespace {
// 由 fields.def 展开的静态定义表
const FieldDef kFieldDefs[] = {
#define HWFP_FIELD(name, key, group, strategy, weight) \
    { FieldKey::k##name, key, group, strategy, weight },
#include "core/fields.def"
#undef HWFP_FIELD
};
static_assert(sizeof(kFieldDefs) / sizeof(kFieldDefs[0]) == (int)FieldKey::kFieldCount,
              "fields.def 与 FieldKey 枚举不一致");
} // namespace

const FieldDef* GetFieldDefs() { return kFieldDefs; }
int GetFieldDefCount() { return (int)FieldKey::kFieldCount; }

const FieldDef* FindFieldDef(FieldKey key) {
    int i = (int)key;
    if (i < 0 || i >= (int)FieldKey::kFieldCount) return nullptr;
    return &kFieldDefs[i];
}

FieldKey FieldKeyFromName(const char* name) {
    if (name)
        for (const auto& d : kFieldDefs)
            if (std::string(d.name) == name) return d.key;
    return FieldKey::kFieldCount;
}

const char* ToString(FpGroup g) {
    switch (g) {
    case FpGroup::Sys:    return "sys";
    case FpGroup::Board:  return "board";
    case FpGroup::Cpu:    return "cpu";
    case FpGroup::Disk:   return "disk";
    case FpGroup::Bios:   return "bios";
    case FpGroup::Memory: return "memory";
    case FpGroup::Os:     return "os";
    case FpGroup::Nic:    return "nic";
    case FpGroup::Gpu:    return "gpu";
    default:              return "none";
    }
}

const char* ToString(MergeStrategy s) {
    switch (s) {
    case MergeStrategy::FirstByPriority: return "first_by_priority";
    case MergeStrategy::Consensus:       return "consensus";
    case MergeStrategy::MergeList:       return "merge_list";
    case MergeStrategy::ConsensusAligned: return "consensus_aligned";
    }
    return "?";
}
