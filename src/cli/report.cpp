#include <windows.h>
#include "cli/report.h"
#include "core/json.h"
#include <cstdio>
#include <map>

namespace {

std::string NowIsoUtc() {
    SYSTEMTIME st;
    GetSystemTime(&st);   // UTC，报告时间仅审计用，不参与指纹
    char b[32];
    std::snprintf(b, sizeof b, "%04u-%02u-%02uT%02u:%02u:%02uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

} // namespace

namespace report {

std::string BuildJson(const CollectorManager::RunResult& rr,
                      const fp::FingerprintOutput& fp,
                      const std::string& tool_version) {
    std::string o = "{";
    o += "\"schema_version\":1";
    o += ",\"tool\":{\"name\":\"hwfp\",\"version\":\"" + json::Escape(tool_version) + "\"}";
    o += ",\"generated_at\":\"" + json::Escape(NowIsoUtc()) + "\"";
    o += ",\"elapsed_ms\":" + json::NumberToString(rr.ms);

    o += ",\"channels\":{\"available\":[";
    // 可用通道从 merged 的 source 集合推导（RunResult 未直接携带）
    std::map<std::string, bool> seen;
    for (const auto& kv : rr.merged)
        for (const auto& r : kv.second)
            if (!r.channel.empty()) seen[r.channel] = true;
    {
        bool first = true;
        for (const auto& s : seen) {
            if (!first) o += ",";
            first = false;
            o += "\"" + json::Escape(s.first) + "\"";
        }
    }
    o += "],\"unavailable\":[";
    for (size_t i = 0; i < rr.unavailable.size(); ++i) {
        if (i) o += ",";
        o += "\"" + json::Escape(rr.unavailable[i]) + "\"";
    }
    o += "]}";

    o += ",\"fingerprint\":{\"algo\":" + json::NumberToString(fp.algo);
    o += ",\"master\":\"" + json::Escape(fp.master) + "\"";
    o += ",\"master_short\":\"" + json::Escape(fp.master.substr(0, 32)) + "\"";  // 前16字节（§3.3 对外指纹）
    o += ",\"sub\":{";
    {
        bool first = true;
        for (const auto& g : fp.sub) {
            if (!first) o += ",";
            first = false;
            o += "\"" + json::Escape(g.first) + "\":\"" + json::Escape(g.second) + "\"";
        }
    }
    o += "}}";

    o += ",\"fields\":[";
    {
        bool first = true;
        for (const auto& kv : rr.merged) {
            const FieldDef* def = FindFieldDef(kv.first);
            for (const auto& r : kv.second) {
                if (!first) o += ",";
                first = false;
                o += "{";
                o += "\"key\":\"" + json::Escape(def ? def->name : "?") + "\"";
                o += ",\"index\":" + json::NumberToString(r.index);
                o += ",\"ok\":" + std::string(r.ok ? "true" : "false");
                o += ",\"placeholder\":" + std::string(r.placeholder ? "true" : "false");
                o += ",\"value\":\"" + json::Escape(r.value) + "\"";
                o += ",\"channel\":\"" + json::Escape(r.channel) + "\"";
                if (!r.confidence.empty())
                    o += ",\"confidence\":\"" + json::Escape(r.confidence) + "\"";
                if (!r.note.empty())
                    o += ",\"note\":\"" + json::Escape(r.note) + "\"";
                o += "}";
            }
        }
    }
    o += "]";
    o += "}";
    return o;
}

bool ParseReport(const std::string& json_text,
                 MergedResults& merged, fp::FingerprintOutput& fp,
                 std::string& err) {
    json::Value root;
    if (!json::Parse(json_text, root, err)) return false;
    if (!root.IsObj()) { err = "报告根必须是对象"; return false; }

    merged.clear();
    fp = fp::FingerprintOutput{};

    const json::Value* fingerprint = nullptr;
    auto fit = root.obj.find("fingerprint");
    if (fit != root.obj.end() && fit->second.IsObj()) fingerprint = &fit->second;
    fp.algo = 0;   // 0 = 算法版本不可知（缺 fingerprint 对象/畸形 algo）
    if (fingerprint) {
        double algo = 0;
        auto ait = fingerprint->obj.find("algo");
        if (ait == fingerprint->obj.end()) {
            fp.algo = 1;   // 无 algo 字段 = 本版本前产出的报告（算法 v1）
        } else if (ait->second.IsNum() && ait->second.number >= 1 &&
                   ait->second.number <= 100000) {
            fp.algo = (int)ait->second.number;   // 经范围校验后才转换
        }   // 其余（字符串/null/越界）保持 0：不可判定 → verify 走 exit 4
        fingerprint->GetStr("master", fp.master);
        auto sit = fingerprint->obj.find("sub");
        if (sit != fingerprint->obj.end() && sit->second.IsObj())
            for (const auto& g : sit->second.obj) fp.sub[g.first] = g.second.str;
    }

    auto flt = root.obj.find("fields");
    if (flt == root.obj.end() || !flt->second.IsArr()) {
        err = "报告缺少 fields 数组";
        return false;
    }
    for (const auto& f : flt->second.arr) {
        std::string key, channel, value;
        double index = 0;
        bool ok = false;
        if (!f.GetStr("key", key) || !f.GetStr("value", value) ||
            !f.GetStr("channel", channel) || !f.GetBool("ok", ok) || !f.GetNum("index", index))
            continue;   // 容忍缺字段（旧版本报告）
        const FieldKey k = FieldKeyFromName(key.c_str());
        if ((int)k >= GetFieldDefCount()) continue;
        FieldResult r;
        r.key = k;
        r.index = (int)index;
        r.channel = channel;
        r.value = value;
        r.ok = ok && !value.empty();
        merged[k].push_back(r);
    }
    return true;
}

} // namespace report
