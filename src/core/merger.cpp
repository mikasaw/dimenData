#include "core/merger.h"
#include "core/textutil.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <map>

namespace {

// 占位符黑名单（R3）：trim + 小写后精确比对。
// 注意不收录 "0"/"1" 这类短值——真实序列号可能形似；列表型噪声由权重 0 兜底。
const char* kPlaceholders[] = {
    "to be filled by o.e.m.", "none", "unknown", "default string",
    "system serial number", "not specified", "invalid", "n/a", "na",
    "empty", "o.e.m.", "oem", "chassis manufacture",
};

std::string LowerTrim(const std::string& s) {
    return textutil::ToLower(textutil::Trim(s));
}

// R2：清零 EAX 低字节（末 2 个 hex 字符，多 socket 下随 vCPU 变化）
std::string MaskApicByte(const std::string& canonical16) {
    if (canonical16.size() != 16) return canonical16;
    std::string s = canonical16;
    s[14] = '0';
    s[15] = '0';
    return s;
}

struct ValidCand {
    const Candidate* c;
    size_t rank;   // 在 valid（优先级序）中的位次，用于并列裁决
};

// 无有效候选时的降级条目（列表型与标量策略输出一致，避免字段整体消失）
FieldResult NoValid(FieldKey key, const std::vector<Candidate>& cands) {
    FieldResult r;
    r.key = key;
    r.candidates = cands;
    r.ok = false;
    for (const auto& c : cands)
        if (c.ok && IsPlaceholder(c.value)) { r.placeholder = true; break; }
    bool anyOk = false;
    for (const auto& c : cands) anyOk = anyOk || c.ok;
    if (anyOk) {
        r.note = "全部候选为占位值（R3 黑名单）";
    } else if (!cands.empty() && !cands.front().note.empty()) {
        r.note = cands.front().note;   // 保留通道给出的降级原因（如"nvidia-smi 未找到"）
    } else {
        r.note = "无有效候选";
    }
    return r;
}

// 实例对齐键排序：全数字键按数值序（"0","2","10" 而非字典序），
// 其余（含无键占位键）按字典序——无键组以  前缀自然排在数字键之后
bool InstanceKeyLess(const std::string& a, const std::string& b) {
    const bool na = !a.empty() && a.find_first_not_of("0123456789") == std::string::npos;
    const bool nb = !b.empty() && b.find_first_not_of("0123456789") == std::string::npos;
    if (na && nb) {
        const unsigned long long va = std::strtoull(a.c_str(), nullptr, 10);
        const unsigned long long vb = std::strtoull(b.c_str(), nullptr, 10);
        if (va != vb) return va < vb;
    }
    return a < b;
}

} // namespace

// R1：SMBIOS Type4 cpu.id（EAX 小端 4 字节 + EDX 小端 4 字节的原始 hex）
// → 与 WMI/CPUID 呈现一致的 "EDX:EAX" 大写 hex（merger.h 导出，指纹层复用）
std::string SmbiosCpuIdToCanonical(const std::string& hex) {
    if (hex.size() != 16) return textutil::ToLower(hex);
    auto nib = [&](int i) -> int {
        const char c = hex[i];
        return (c >= '0' && c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10;
    };
    uint32_t bytes[8];
    for (int i = 0; i < 8; ++i)
        bytes[i] = (uint32_t)(nib(i * 2) * 16 + nib(i * 2 + 1));
    const uint32_t eax = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
    const uint32_t edx = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | ((uint32_t)bytes[7] << 24);
    char b[17] = {};
    std::snprintf(b, sizeof b, "%08X%08X", edx, eax);
    return b;
}

bool IsPlaceholder(const std::string& raw) {
    const std::string v = LowerTrim(raw);
    if (v.empty()) return true;
    for (const char* p : kPlaceholders)
        if (v == p) return true;
    return false;
}

// 实例对齐键归一：去分隔符 + 大写。磁盘 Index（纯数字）原样通过，
// MAC 的 wmi/native 形态差异在此吸收——配对发生在组键上，值不受影响
std::string NormalizeInstanceKey(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (const char c : raw) {
        if (c == ':' || c == '-' || c == ' ' || c == '.') continue;
        out += (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
    }
    return out;
}

std::string NormalizeForCompare(FieldKey key, const std::string& channel,
                                const std::string& raw) {
    const std::string t = textutil::Trim(raw);
    if (key == FieldKey::kCpuId) {
        // R1：SMBIOS 与 WMI/CPUID 呈现互为字节序；先统一再 R2 屏蔽
        std::string canonical = (channel == "smbios") ? SmbiosCpuIdToCanonical(t)
                                                      : textutil::ToLower(t);
        return MaskApicByte(textutil::ToLower(canonical));
    }
    if (key == FieldKey::kDiskSerial) {
        // R4：磁盘序列号跨通道比较需吸收分隔符/空格差异
        // （如 WMI NVMe 的 "A1B2_C3D4_E5F6_0007." 与去分隔形式）
        std::string out;
        out.reserve(t.size());
        for (char c : t) {
            if (c == ' ' || c == ':' || c == '-' || c == '_' || c == '.') continue;
            out += (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
        }
        return out;
    }
    return LowerTrim(t);
}

MergedResults MergeAll(const std::map<FieldKey, std::vector<Candidate>>& by_key,
                       const std::map<FieldKey, MergeStrategy>* strategy_override) {
    MergedResults out;

    for (const auto& kv : by_key) {
        const FieldKey key = kv.first;
        const auto& cands  = kv.second;

        const FieldDef* def = FindFieldDef(key);
        MergeStrategy st = def ? def->strategy : MergeStrategy::FirstByPriority;
        if (strategy_override) {
            auto it = strategy_override->find(key);
            if (it != strategy_override->end()) st = it->second;
        }

        // 有效候选：有值且非占位符（保留占位标记供诊断）
        std::vector<ValidCand> valid;
        for (const auto& c : cands)
            if (c.ok && !IsPlaceholder(c.value)) valid.push_back({&c, valid.size()});

        FieldResult r;
        r.key = key;
        r.candidates = cands;

        if (st == MergeStrategy::MergeList) {
            if (valid.empty()) {   // 与标量策略一致：字段保留但标记无有效值
                out[key].push_back(NoValid(key, cands));
                continue;
            }
            // 列表合并：按比较归一化分组，组内记录各通道出现次数，
            // 输出条数 = 各通道计数的最大值（多重重集语义）——
            // 跨通道去重的同时保留实例数（如 2 条同规格内存，矩阵 R8 条数语义）
            std::vector<std::pair<std::string, std::vector<const ValidCand*>>> groups;
            std::map<std::string, size_t> gidx;
            for (const auto& vc : valid) {
                const std::string norm = NormalizeForCompare(key, vc.c->channel, vc.c->value);
                auto it = gidx.find(norm);
                if (it == gidx.end()) {
                    it = gidx.emplace(norm, groups.size()).first;
                    groups.push_back({norm, {}});
                }
                groups[it->second].second.push_back(&vc);
            }
            int next_index = 0;   // 跨组连续重排（组内多重度也占 index）
            for (const auto& g : groups) {
                std::map<std::string, int> per_channel;
                for (const auto* vc : g.second) per_channel[vc->c->channel]++;
                int multiplicity = 0;
                for (const auto& pc : per_channel)
                    multiplicity = std::max(multiplicity, pc.second);
                const Candidate* rep = g.second.front()->c;   // 最高优先级首现为代表
                for (int k = 0; k < multiplicity; ++k) {
                    FieldResult e = r;
                    e.index   = next_index++;
                    e.value   = rep->value;
                    e.channel = rep->channel;
                    e.note    = g.second.size() > 1 ? "跨通道一致(" +
                                std::to_string(g.second.size()) + ")" : rep->note;
                    e.ok      = true;
                    out[key].push_back(e);
                }
            }
            continue;
        }

        if (st == MergeStrategy::ConsensusAligned) {
            if (valid.empty()) {
                out[key].push_back(NoValid(key, cands));
                continue;
            }
            // 实例对齐：按 instance_key 把各通道的同一实例配对（如磁盘按盘位号），
            // 组内做跨通道一致性投票；输出按盘位键排序并重排 index。
            // 无键候选各自独立成组（排在键组之后），不参与跨通道配对。
            struct Group {
                std::string key;
                int  unkeyed_order = -1;   // >=0 表示无键组，按生成序排在有键组之后
                std::vector<const ValidCand*> cands;
            };
            std::vector<Group> groups;
            std::map<std::string, size_t> gidx;
            int unkeyed = 0;
            for (const auto& vc : valid) {
                std::string k = NormalizeInstanceKey(vc.c->instance_key);
                int order = -1;
                if (k.empty()) {
                    order = unkeyed++;
                    k = std::string(1, (char)1) + std::to_string(order);
                }
                auto it = gidx.find(k);
                if (it == gidx.end()) {
                    it = gidx.emplace(k, groups.size()).first;
                    groups.push_back(Group{k, order, {}});
                }
                groups[it->second].cands.push_back(&vc);
            }
            std::stable_sort(groups.begin(), groups.end(),
                             [](const Group& a, const Group& b) {
                                 const bool keyedA = a.unkeyed_order < 0;
                                 const bool keyedB = b.unkeyed_order < 0;
                                 if (keyedA != keyedB) return keyedA;   // 有键组在前
                                 if (keyedA) return InstanceKeyLess(a.key, b.key);
                                 return a.unkeyed_order < b.unkeyed_order;   // 无键按生成序
                             });
            int next_index = 0;
            for (const auto& g : groups) {
                // 组内一致性投票：归一化值 → 候选（保持优先级序）
                std::map<std::string, std::vector<const ValidCand*>> votes;
                for (const auto* vc : g.cands)
                    votes[NormalizeForCompare(key, vc->c->channel, vc->c->value)].push_back(vc);
                const std::vector<const ValidCand*>* best = nullptr;
                for (const auto& v : votes)
                    if (!best || v.second.size() > best->size() ||
                        (v.second.size() == best->size() &&
                         v.second.front()->rank < best->front()->rank))
                        best = &v.second;

                FieldResult e = r;
                e.index  = next_index++;
                e.instance_key = g.unkeyed_order < 0 ? g.key : std::string();  // 保留盘位号供追溯
                e.value  = best->front()->c->value;   // 一致组代表（并列取最高优先级）
                e.channel = best->front()->c->channel;
                e.ok     = true;
                if (best->size() >= 2) {
                    e.confidence = "high";
                    e.note = "实例对齐跨通道一致(键 " + g.key + ")";
                } else if (g.cands.size() >= 2) {
                    e.confidence = "fallback";
                    e.note = "实例 " + g.key + " 跨通道分歧(" +
                             std::to_string(g.cands.size()) + ")，取最高优先级";
                } else {
                    e.confidence = "single";
                    e.note = best->front()->c->note;
                }
                out[key].push_back(e);
            }
            continue;
        }

        // 标量字段：FirstByPriority / Consensus
        r.index = 0;
        if (valid.empty()) {
            out[key].push_back(NoValid(key, cands));
            continue;
        }

        if (st == MergeStrategy::Consensus && valid.size() >= 2) {
            // 分组：组大小最大者胜；并列取含最高优先级候选（valid 序靠前）的组。
            // groups 保持首现序（即优先级序），front 的 valid 下标即组内最高优先级排名
            std::vector<std::pair<std::string, std::vector<const ValidCand*>>> groups;
            std::map<std::string, size_t> gidx;
            for (size_t rank = 0; rank < valid.size(); ++rank) {
                const std::string norm =
                    NormalizeForCompare(key, valid[rank].c->channel, valid[rank].c->value);
                auto it = gidx.find(norm);
                if (it == gidx.end()) {
                    it = gidx.emplace(norm, groups.size()).first;
                    groups.push_back({norm, {}});
                }
                groups[it->second].second.push_back(&valid[rank]);
            }
            size_t best = 0;
            for (size_t gi = 1; gi < groups.size(); ++gi) {
                if (groups[gi].second.size() > groups[best].second.size() ||
                    (groups[gi].second.size() == groups[best].second.size() &&
                     groups[gi].second.front()->rank < groups[best].second.front()->rank))
                    best = gi;   // 并列时 front 指针序 = valid 序 = 优先级序
            }
            if (groups[best].second.size() >= 2) {
                const Candidate* hit = groups[best].second.front()->c;
                r.value      = hit->value;
                r.channel    = hit->channel;
                r.confidence = "high";
                r.note       = "双通道交叉验证一致";
                r.ok         = true;
                out[key].push_back(r);
                continue;
            }
            // 全部分歧：取最高优先级候选并留痕
            r.value      = valid.front().c->value;
            r.channel    = valid.front().c->channel;
            r.confidence = "fallback";
            r.note       = "多通道分歧(" + std::to_string(valid.size()) + ")，取最高优先级";
            r.ok         = true;
            out[key].push_back(r);
            continue;
        }

        // 单候选 / FirstByPriority：取第一个有效候选（即最高优先级）
        r.value      = valid.front().c->value;
        r.channel    = valid.front().c->channel;
        r.confidence = valid.size() >= 2 ? "single" : "";
        r.note       = valid.front().c->note;
        r.ok         = true;
        out[key].push_back(r);
    }
    return out;
}
