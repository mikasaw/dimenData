// ============================================================
// T8 JSON 解析/序列化 + 配置加载 + 报告往返单测
// ============================================================
#include "tests/test_util.h"
#include "cli/report.h"
#include "core/json.h"
#include "core/config.h"
#include "core/collector_manager.h"
#include "core/field.h"
#include "core/field_result.h"
#include "fingerprint/fingerprint_engine.h"
#include <string>

TEST(report, roundtrip_and_tamper_detection) {
    // 报告构建 → 回读 → 重算指纹一致（完整性）；篡改字段后重算值必须变化
    CollectorManager::RunResult rr;
    FieldResult r1;
    r1.key = FieldKey::kOsBuild; r1.channel = "registry"; r1.value = "26200"; r1.ok = true;
    FieldResult r2;
    r2.key = FieldKey::kBoardSerial; r2.channel = "smbios"; r2.value = "BRD-1"; r2.ok = true;
    rr.merged[FieldKey::kOsBuild] = {r1};
    rr.merged[FieldKey::kBoardSerial] = {r2};
    rr.instances = 2;

    const auto fp = fp::ComputeFingerprint(rr.merged);
    const std::string text = report::BuildJson(rr, fp, "0.1.0");

    MergedResults back;
    fp::FingerprintOutput old_fp;
    std::string err;
    CHECK(report::ParseReport(text, back, old_fp, err));
    // 算法版本戳往返（本次改动核心机制）
    CHECK_EQ(old_fp.algo, fp::kAlgoVersion);     // 报告写出 algo=2 并被回读
    {
        // 去掉 algo 键 = 旧版报告 → 回读为 v1
        std::string legacy = text;
        const std::string needle = "\"algo\":" + std::to_string(fp::kAlgoVersion) + ",";
        const size_t pos = legacy.find(needle);
        CHECK(pos != std::string::npos);
        if (pos != std::string::npos) legacy.erase(pos, needle.size());
        MergedResults lm;
        fp::FingerprintOutput lfp;
        CHECK(report::ParseReport(legacy, lm, lfp, err));
        CHECK_EQ(lfp.algo, 1);
    }
    {
        // 畸形 algo（字符串）→ 不可知（0，verify 将走 exit 4 分支）
        std::string bad = text;
        const std::string needle = "\"algo\":" + std::to_string(fp::kAlgoVersion);
        const size_t pos = bad.find(needle);
        CHECK(pos != std::string::npos);
        if (pos != std::string::npos) bad.replace(pos, needle.size(), "\"algo\":\"x\"");
        MergedResults bm;
        fp::FingerprintOutput bfp;
        CHECK(report::ParseReport(bad, bm, bfp, err));
        CHECK_EQ(bfp.algo, 0);
    }
    const auto recomputed = fp::ComputeFingerprint(back);
    CHECK_STREQ(recomputed.master, fp.master);   // 回读重算 == 原指纹

    // 守卫后再取：ParseReport 回归失败时给出断言而非越界崩溃
    CHECK(back.count(FieldKey::kBoardSerial) == 1);
    if (back.count(FieldKey::kBoardSerial) == 1 && !back[FieldKey::kBoardSerial].empty())
        back[FieldKey::kBoardSerial][0].value = "TAMPERED";   // 篡改参与指纹字段（权重20）
    const auto tampered = fp::ComputeFingerprint(back);
    CHECK(tampered.master != fp.master);         // 重算值变化 → 可检出
}

TEST(json, parse_roundtrip_basics) {
    json::Value v;
    std::string err;
    const char* text =
        "{\"a\": 1, \"b\": \"x,y\\nz\", \"c\": true, \"d\": [1,2,{\"e\":null}],"
        " \"f\": -2.5}";
    CHECK(json::Parse(text, v, err));
    CHECK(v.IsObj());
    double num = 0;
    CHECK(v.GetNum("a", num) && num == 1);
    std::string s;
    CHECK(v.GetStr("b", s));
    CHECK_STREQ(s, "x,y\nz");              // 转义还原
    bool b = false;
    CHECK(v.GetBool("c", b) && b);
    auto dit = v.obj.find("d");
    CHECK(dit != v.obj.end() && dit->second.IsArr());
    CHECK_EQ((int)dit->second.arr.size(), 3);
    CHECK(json::Parse("{\"x\":}", v, err) == false);   // 语法错误
    CHECK(!err.empty());
}

TEST(json, escape_output) {
    CHECK_STREQ(json::Escape("a\"b\\c\n\t"), "a\\\"b\\\\c\\n\\t");
    CHECK_STREQ(json::Escape("中文"), "中文");           // UTF-8 透传
    CHECK_STREQ(json::Escape(std::string(1, (char)1)), "\\u0001");
    CHECK_STREQ(json::NumberToString(42), "42");          // 整数不带小数点
    CHECK_STREQ(json::NumberToString(1.5), "1.5");
}

TEST(json, rejects_nonfinite_numbers) {
    // 溢出（1e999 → strtod 得 inf）在解析层拒绝：NumberToString 会产出
    // "inf"，自家解析器不认——非有限值不允许进入 Value
    json::Value v;
    std::string err;
    CHECK(!json::Parse("1e999", v, err));
    CHECK(!err.empty());
    CHECK(!json::Parse("-1e999", v, err));
    CHECK(json::Parse("1e-999", v, err));                 // 下溢为 0 仍接受
    CHECK(v.IsNum() && v.number == 0);
}

TEST(json, number_text_is_idempotent) {
    // 数值文本必须自稳定：dump → parse → dump 得到同一文本
    // （%.6g 时代 1234567890.5 → "1.23457e+09" → 重解析 1234570000，文本漂移）
    const char* nums[] = { "1234567890.5", "1.25e-8", "0.1", "-2.75", "1e15",
                           "123456789012345678" };
    for (const char* n : nums) {
        json::Value v;
        std::string err;
        CHECK(json::Parse(n, v, err));
        if (!v.IsNum()) continue;
        const std::string d1 = json::NumberToString(v.number);
        json::Value v2;
        CHECK(json::Parse(d1, v2, err));
        CHECK_STREQ(json::NumberToString(v2.number), d1);
    }
    CHECK_STREQ(json::NumberToString(42), "42");          // 整数路径不受影响
}

TEST(config, load_channels_fields_execution) {
    const char* text = R"({
        "channels": {
            "wmi":     { "enabled": false },
            "smbios":  { "enabled": true, "priority": 5 }
        },
        "fields": {
            "board.serial": { "strategy": "first_by_priority" },
            "disk.*":       { "strategy": "consensus_aligned" },
            "memory.*":     { "strategy": "merge_list", "weight": 0 }
        },
        "execution": { "max_workers": 8, "per_task_timeout_ms": 1500 },
        "output": { "path": "out.json", "text": false }
    })";
    HwfpConfig cfg;
    std::string err;
    CHECK(cfg.LoadFromText(text, err));

    CHECK_EQ((int)cfg.channels.size(), 2);
    CHECK(!cfg.channels["wmi"].enabled);
    CHECK(cfg.channels["smbios"].enabled && cfg.channels["smbios"].priority == 5);

    CHECK_EQ((int)cfg.field_strategy.size(), 9);   // board 1 + disk.* 4 + memory.* 4
    CHECK(cfg.field_strategy[FieldKey::kBoardSerial] == MergeStrategy::FirstByPriority);
    CHECK(cfg.field_strategy[FieldKey::kDiskSerial] == MergeStrategy::ConsensusAligned);
    CHECK(cfg.field_strategy.count(FieldKey::kMemorySerial) == 1);
    CHECK_EQ((int)cfg.field_weight.size(), 4);     // memory.* 权重展开 4 个
    CHECK_EQ(cfg.field_weight[FieldKey::kMemorySize], 0);

    CHECK_EQ((int)cfg.workers, 8);
    CHECK_EQ(cfg.per_task_timeout_ms, 1500);
    CHECK_STREQ(cfg.output_path, "out.json");
    CHECK(!cfg.text_mode);
}

TEST(config, rejects_bad_strategy_and_garbage) {
    HwfpConfig cfg;
    std::string err;
    CHECK(!cfg.LoadFromText("{\"fields\":{\"a.b\":{\"strategy\":\"magic\"}}}", err));
    CHECK(!cfg.LoadFromText("not json at all", err));
    CHECK(!cfg.LoadFromText("[1,2]", err));
}

TEST(config, numeric_range_guards) {
    // 数值按 double 承载：超出 int/size_t 可转域的值必须显式报错（UB 转型防线）
    HwfpConfig cfg;
    std::string err;
    CHECK(!cfg.LoadFromText("{\"execution\":{\"max_workers\":257}}", err));
    CHECK(!cfg.LoadFromText("{\"execution\":{\"max_workers\":1e30}}", err));
    CHECK(!cfg.LoadFromText("{\"execution\":{\"per_task_timeout_ms\":1e30}}", err));
    CHECK(!cfg.LoadFromText("{\"fields\":{\"cpu.id\":{\"weight\":1e30}}}", err));
    CHECK(!cfg.LoadFromText("{\"channels\":{\"wmi\":{\"priority\":1e30}}}", err));
    CHECK(!cfg.LoadFromText("{\"channels\":{\"wmi\":{\"tpm_probe\":1e30}}}", err));
    CHECK(!err.empty());

    CHECK(cfg.LoadFromText("{\"execution\":{\"max_workers\":256}}", err));
    CHECK_EQ((int)cfg.workers, 256);
    HwfpConfig fresh;   // 新对象：非正数 max_workers 不改写默认值（自动档）
    CHECK(fresh.LoadFromText("{\"execution\":{\"max_workers\":0}}", err));
    CHECK_EQ((int)fresh.workers, 0);
}
