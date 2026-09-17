#include "core/config.h"
#include "core/json.h"
#include <cmath>
#include <functional>
#include <fstream>
#include <sstream>

namespace {

// double → 整型的安全转域判定：JSON 数值按 double 承载，1e30 这类有限值
// 直接 (int)/(size_t) 转型是 UB，必须先落域
bool IntRange(double v, double lo, double hi) {
    return std::isfinite(v) && v >= lo && v <= hi;
}

// 展开 "xxx.*" 通配到该前缀全部字段键；精确名直接查。
// 返回 false = 精确字段名未知（疑似拼写错误），由调用方报错
bool ExpandFieldPattern(const std::string& pattern,
                        const std::function<void(FieldKey)>& fn) {
    if (pattern.size() > 2 && pattern.compare(pattern.size() - 2, 2, ".*") == 0) {
        const std::string prefix = pattern.substr(0, pattern.size() - 1);  // 含 '.'
        for (int i = 0; i < GetFieldDefCount(); ++i) {
            const FieldDef& d = GetFieldDefs()[i];
            const std::string n(d.name);
            if (n.size() > prefix.size() && n.compare(0, prefix.size(), prefix) == 0)
                fn(d.key);
        }
        return true;
    }
    const FieldKey k = FieldKeyFromName(pattern.c_str());
    if ((int)k >= GetFieldDefCount()) return false;
    fn(k);
    return true;
}

} // namespace

bool HwfpConfig::LoadFromText(const std::string& text, std::string& err) {
    json::Value root;
    if (!json::Parse(text, root, err)) return false;
    if (!root.IsObj()) { err = "配置根必须是对象"; return false; }

    if (root.obj.count("channels")) {
        const json::Value& ch = root.obj.at("channels");
        if (!ch.IsObj()) { err = "channels 必须是对象"; return false; }
        for (const auto& kv : ch.obj) {
            ChannelConf cc;
            double num = 0;
            bool b = false;
            if (kv.second.GetBool("enabled", b)) cc.enabled = b;
            if (kv.second.GetNum("priority", num)) {
                if (!IntRange(num, -100000, 100000)) {
                    err = "priority 超出范围(-100000..100000): " + kv.first;
                    return false;
                }
                cc.priority = (int)num;
            }
            for (const auto& o : kv.second.obj) {
                // 其余数值键作为通道选项下发（如 wmi 的 tpm_probe）
                if (o.first == "enabled" || o.first == "priority") continue;
                if (o.second.IsNum()) {
                    if (!IntRange(o.second.number, -100000, 100000)) {
                        err = "通道选项数值超出范围(-100000..100000): " +
                              kv.first + "." + o.first;
                        return false;
                    }
                    cc.options[o.first] = (int)o.second.number;
                }
            }
            channels[kv.first] = cc;
        }
    }

    if (root.obj.count("fields")) {
        const json::Value& fs = root.obj.at("fields");
        if (!fs.IsObj()) { err = "fields 必须是对象"; return false; }
        for (const auto& kv : fs.obj) {
            std::string strategy;
            double weight = 0;
            if (kv.second.GetStr("strategy", strategy)) {
                MergeStrategy st = MergeStrategy::FirstByPriority;
                if (strategy == "first_by_priority") st = MergeStrategy::FirstByPriority;
                else if (strategy == "consensus") st = MergeStrategy::Consensus;
                else if (strategy == "merge_list") st = MergeStrategy::MergeList;
                else if (strategy == "consensus_aligned") st = MergeStrategy::ConsensusAligned;
                else { err = "未知归并策略: " + strategy; return false; }
                if (!ExpandFieldPattern(kv.first,
                        [&](FieldKey k) { field_strategy[k] = st; })) {
                    err = "未知字段名: " + kv.first;
                    return false;
                }
            }
            if (kv.second.GetNum("weight", weight)) {
                if (!IntRange(weight, -100000, 100000)) {
                    err = "字段权重超出范围(-100000..100000): " + kv.first;
                    return false;
                }
                if (!ExpandFieldPattern(kv.first,
                        [&](FieldKey k) { field_weight[k] = (int)weight; })) {
                    err = "未知字段名: " + kv.first;
                    return false;
                }
            }
        }
    }

    if (root.obj.count("execution")) {
        const json::Value& ex = root.obj.at("execution");
        double num = 0;
        if (ex.GetNum("max_workers", num)) {
            if (num > 0 && !IntRange(num, 1, 256)) {
                err = "max_workers 应在 1..256";   // 非正数沿用自动档
                return false;
            }
            if (num > 0) workers = (size_t)num;
        }
        if (ex.GetNum("per_task_timeout_ms", num)) {
            if (num > 0 && !IntRange(num, 1, 3600000)) {
                err = "per_task_timeout_ms 应在 1..3600000";
                return false;
            }
            if (num > 0) per_task_timeout_ms = (int)num;
        }
    }

    if (root.obj.count("output")) {
        const json::Value& op = root.obj.at("output");
        op.GetStr("path", output_path);
        bool b = false;
        if (op.GetBool("text", b)) text_mode = b;
    }
    return true;
}

bool HwfpConfig::LoadFromFile(const std::string& path, std::string& err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { err = "无法打开配置文件: " + path; return false; }
    std::ostringstream os;
    os << f.rdbuf();
    return LoadFromText(os.str(), err);
}
