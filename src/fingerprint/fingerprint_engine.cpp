#include "fingerprint/fingerprint_engine.h"
#include "fingerprint/sha256.h"
#include "core/textutil.h"
#include <algorithm>
#include <set>

namespace fp {
namespace {

int WeightOf(const FieldDef& def, const std::map<FieldKey, int>* override_w) {
    if (override_w) {
        auto it = override_w->find(def.key);
        if (it != override_w->end()) return it->second;
    }
    return def.weight;
}

// 无分隔符 + 大写（MAC/序列号通用）
std::string CompactUpper(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == ' ' || c == ':' || c == '-' || c == '_' || c == '.') continue;
        out += (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
    }
    return out;
}

} // namespace

std::string NormalizeValueForFingerprint(FieldKey key, const std::string& channel,
                                         const std::string& raw) {
    std::string v = textutil::Trim(raw);
    if (v.empty()) return {};
    switch (key) {
    case FieldKey::kCpuId: {
        // R1：smbios 来源先转 canonical；R2：清零 EAX 低字节
        std::string canonical =
            (channel == "smbios") ? SmbiosCpuIdToCanonical(v) : textutil::ToLower(v);
        canonical = textutil::ToLower(canonical);
        if (canonical.size() == 16) {
            canonical[14] = '0';
            canonical[15] = '0';
        }
        return canonical;
    }
    case FieldKey::kDiskSerial:
        return CompactUpper(v);          // R4：下划线/点/连字符与空格差异
    case FieldKey::kNicMac:
        return CompactUpper(v);
    case FieldKey::kBiosReleaseDate: {
        // smbios "MM/DD/YYYY" → ISO；wmi 侧已在通道层转 ISO
        if (v.size() == 10 && v[2] == '/' && v[5] == '/')
            return v.substr(6, 4) + "-" + v.substr(0, 2) + "-" + v.substr(3, 2);
        return v;
    }
    default:
        return v;
    }
}

FingerprintOutput ComputeFingerprint(const MergedResults& merged,
                                     const std::map<FieldKey, int>* weight_override) {
    // 参与行：weight>0 且有效值；行 = "字段键=规范化值"
    struct Line { std::string key_name; std::string value; FpGroup group; };
    std::vector<Line> lines;

    for (const auto& kv : merged) {
        const FieldDef* def = FindFieldDef(kv.first);
        if (!def || WeightOf(*def, weight_override) <= 0) continue;
        for (const auto& r : kv.second) {
            if (!r.ok || r.value.empty()) continue;
            std::string v = NormalizeValueForFingerprint(kv.first, r.channel, r.value);
            if (v.empty()) continue;
            lines.push_back({def->name, v, def->group});
        }
    }

    // 确定性：按 (键名, 值) 排序（列表字段实例顺序不再影响指纹）
    std::sort(lines.begin(), lines.end(), [](const Line& a, const Line& b) {
        return a.key_name != b.key_name ? a.key_name < b.key_name
                                        : a.value < b.value;
    });

    FingerprintOutput out;
    for (const auto& l : lines)
        out.contributors.push_back(l.key_name + "=" + l.value);

    // 子指纹（按组），再汇总整机
    std::map<std::string, std::vector<std::string>> by_group;
    {
        size_t i = 0;
        for (const auto& l : lines) {
            by_group[ToString(l.group)].push_back(out.contributors[i++]);
        }
    }
    for (const auto& g : by_group) {
        std::string payload = "HWFP-V1-" + g.first + "\n";
        for (const auto& c : g.second) payload += c + "\n";
        out.sub[g.first] = Sha256Hex(payload);
    }

    std::string payload = "HWFP-V1\n";
    for (const auto& c : out.contributors) payload += c + "\n";
    out.master = Sha256Hex(payload);
    return out;
}

double Similarity(const FingerprintOutput& a, const FingerprintOutput& b,
                  const std::map<FieldKey, int>* weight_override) {
    // 组权重 = 组内字段权重和（weight>0 者；随 weight_override 联动）。
    // 只统计两侧出现的组的并集：两边都缺失的组不计入（缺失-缺失视为一致但无信息量）
    std::map<std::string, double> weight;
    for (int i = 0; i < GetFieldDefCount(); ++i) {
        const FieldDef& d = GetFieldDefs()[i];
        if (WeightOf(d, weight_override) <= 0) continue;
        weight[ToString(d.group)] += WeightOf(d, weight_override);
    }
    std::set<std::string> groups;
    for (const auto& g : a.sub) groups.insert(g.first);
    for (const auto& g : b.sub) groups.insert(g.first);
    double total = 0, hit = 0;
    for (const auto& g : groups) {
        auto it = weight.find(g);
        if (it == weight.end()) continue;   // 无权重组（防御）
        total += it->second;
        if (a.sub.count(g) && b.sub.count(g) && a.sub.at(g) == b.sub.at(g))
            hit += it->second;
    }
    return total > 0 ? hit / total : 0.0;
}

} // namespace fp
