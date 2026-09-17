// ============================================================
// 模糊测试入口（零依赖、确定性种子、内建判定 oracle）
// 覆盖六个目标（uuid 并入 nvidiasmi），每轮断言"不崩溃 + 行为契约"：
//   json       解析/序列化 —— 成功则 dump→parse→dump 幂等；失败必须给错误信息
//   config     配置加载 —— 已知字段名必须成功、未知必须报错；数值越界拒绝
//   smbios     SMBIOS 表 —— 合法表精确还原；任意变异/截断不越界、输出串长有界
//   edid       EDID 头 —— 合法块还原厂码/产品号/序列号；输出形态受控
//   nvidiasmi  CSV 解析 —— 与独立重实现的行切分逻辑逐字段对账（差异测试）
//   uuid       GPU UUID 形态 —— 与独立重实现的严格判定全量等价
//   pipeline   归并+指纹+报告 —— 结构不变量、相似度边界、报告往返指纹一致
// 用法: build.cmd fuzz [轮数=200000] [种子]
//       失败打印 目标/轮次/描述 与输入十六进制预览，并落盘
//       build/fuzz_repro_<target>.bin；同参数重跑可复现（Rng 全确定性）。
// ============================================================
#include "channels/native_util.h"
#include "channels/registry_parser.h"
#include "channels/smbios_parser.h"
#include "cli/report.h"
#include "core/config.h"
#include "core/field.h"
#include "core/field_result.h"
#include "core/json.h"
#include "core/merger.h"
#include "fingerprint/fingerprint_engine.h"
#include "license/crypto.h"
#include "license/license.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace fz {

// ---------- 确定性随机（xorshift64*） ----------
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    uint64_t Next() {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        return s * 0x2545F4914F6CDD1Dull;
    }
    uint32_t U32() { return (uint32_t)(Next() >> 32); }
    size_t Range(size_t n) { return n ? (size_t)(U32() % n) : 0; }
    uint8_t Byte() { return (uint8_t)U32(); }
};

// ---------- 失败记录与复现落盘 ----------
constexpr int kMaxReports = 20;   // 单目标失败上报上限（防止刷屏；计数仍累计）

std::string Clip(const std::string& s, size_t n = 120) {
    if (s.size() <= n) return s;
    return s.substr(0, n) + "...";
}

struct Fuzz {
    const char* target = "";
    uint64_t    seed = 0;
    int         round = 0;
    long long   cases = 0;
    long long   failures = 0;
    bool        muted = false;   // 达到上报上限后静默（继续跑完统计）

    void Fail(const std::string& what, const std::string& input) {
        ++failures;
        if (muted) return;
        if (failures > kMaxReports) { muted = true; return; }
        std::printf("[FAIL] %-10s round=%d %s\n", target, round, what.c_str());
        DumpRepro(input);
    }

private:
    void DumpRepro(const std::string& input) const {
        const std::string name = std::string("fuzz_repro_") + target + ".bin";
        std::string where = "build/" + name;
        std::ofstream f(where.c_str(), std::ios::binary | std::ios::trunc);
        if (!f) {   // build/ 目录不存在时退回当前目录
            where = name;
            f.open(name.c_str(), std::ios::binary | std::ios::trunc);
        }
        if (!f) {
            std::printf("       input %llu bytes (repro dump failed)\n",
                        (unsigned long long)input.size());
            return;
        }
        f.write(input.data(), (std::streamsize)input.size());
        std::printf("       input %llu bytes -> %s  hex:",
                    (unsigned long long)input.size(), where.c_str());
        const size_t n = input.size() < 48 ? input.size() : 48;
        for (size_t i = 0; i < n; ++i)
            std::printf(" %02X", (unsigned char)input[i]);
        std::printf("\n");
    }
};

// ---------- 合成输入构件（与单测夹具同源的合法基线） ----------

// JSON 文本变异
std::string MutateText(Rng& r, const std::string& base) {
    static const char kAlph[] = "{}[]\":,0123456789.eE+-truefalsn\\ \t\r\n!@#$%^&*()<>=;'/?:|~`";
    std::string s = base;
    const int ops = 1 + (int)r.Range(3);
    for (int i = 0; i < ops; ++i) {
        const size_t n = s.size();
        switch (r.Range(6)) {
        case 0: if (n) s[r.Range(n)] = (char)r.Byte(); break;                        // 翻字节
        case 1: if (n) s.erase(r.Range(n), 1); break;                                // 删字节
        case 2: s.insert(s.begin() + (ptrdiff_t)r.Range(n + 1),
                         kAlph[r.Range(sizeof kAlph - 1)]); break;                   // 插字节
        case 3: if (n) s.resize(r.Range(n + 1)); break;                              // 截断
        case 4: s.append(r.Range(8), (char)r.Byte()); break;                         // 追加随机
        case 5: if (n) {                                                             // 复制片段
                    const size_t from = r.Range(n);
                    s.insert(r.Range(s.size() + 1), s.substr(from, r.Range(n - from + 1)));
                } break;
        default: break;
        }
        if (s.size() > 4096) s.resize(4096);
    }
    return s;
}

std::vector<uint8_t> MutateBytes(Rng& r, const std::vector<uint8_t>& base, int max_flips) {
    std::vector<uint8_t> v = base;
    const int flips = 1 + (int)r.Range((size_t)max_flips);
    for (int i = 0; i < flips && !v.empty(); ++i)
        v[r.Range(v.size())] = (uint8_t)r.Byte();
    return v;
}

// ============================================================
// 目标 1：JSON 解析/序列化
// ============================================================

// 本地序列化（对象键 map 有序 → 输出确定），供幂等 oracle 使用
std::string DumpValue(const json::Value& v) {
    using T = json::Value;
    switch (v.type) {
    case T::Null: return "null";
    case T::Bool: return v.boolean ? "true" : "false";
    case T::Num:  return json::NumberToString(v.number);
    case T::Str:  return "\"" + json::Escape(v.str) + "\"";
    case T::Arr: {
        std::string s = "[";
        for (size_t i = 0; i < v.arr.size(); ++i) {
            if (i) s += ",";
            s += DumpValue(v.arr[i]);
        }
        return s + "]";
    }
    case T::Obj: {
        std::string s = "{";
        bool first = true;
        for (const auto& kv : v.obj) {
            if (!first) s += ",";
            first = false;
            s += "\"" + json::Escape(kv.first) + "\":" + DumpValue(kv.second);
        }
        return s + "}";
    }
    }
    return "?";
}

void CheckJsonText(Fuzz& f, const std::string& text) {
    f.cases++;
    json::Value v;
    std::string err;
    if (!json::Parse(text, v, err)) {
        if (err.empty()) f.Fail("parse failed without error message", text);
        return;
    }
    if (!err.empty()) f.Fail("parse ok but error message set", text);
    const std::string d1 = DumpValue(v);
    json::Value v2;
    std::string err2;
    if (!json::Parse(d1, v2, err2))
        f.Fail("dump not reparseable: " + err2 + " dump=" + Clip(d1), text);
    else if (DumpValue(v2) != d1)
        f.Fail("dump not idempotent: " + Clip(d1), text);
}

const char* kJsonOk[] = {
    "{}", "[]", "null", "true", "false", "0", "-0", "1.5", "-2.5e10", "1e-7",
    "\"s\"", "\"\"", "\"\\u4e2d\\u6587\"", "\"a\\\"b\\\\c\\n\\t\\b\\f\\/\"",
    "{\"a\":1}", "[1,2,3]", "{\"a\":{\"b\":[true,false,null,\"x\"]}}",
    "{\"big\":123456789012345,\"neg\":-987654321,\"exp\":1.25e-8}",
    " { \"spaced\" : [ 1 , 2 ] } ",
    "{\"tab\":\"\\t\",\"ctrl\":\"\\u0001\",\"utf8\":\"值\"}",
};
const char* kJsonBad[] = {
    "", "  ", "{", "}", "[1,2", "{\"a\":}", "tru", "\"unclosed",
    "{\"a\":1}x", "1.2.3", "-", "1e", "nan", "Infinity", "\"a\\u00\"", "1e999",
};

std::string DeepNest(int levels) {
    std::string s;
    for (int i = 0; i < levels; ++i) s += "[";
    s += "1";
    for (int i = 0; i < levels; ++i) s += "]";
    return s;
}

void FuzzJson(Fuzz& f, Rng& r, long long rounds) {
    // oracle 自检：正向/负向基线必须全部符合预期（防 oracle 本身失效）
    for (const char* t : kJsonOk) {
        json::Value v; std::string err;
        if (!json::Parse(t, v, err))
            f.Fail(std::string("selfcheck: valid corpus rejected: ") + t, t);
    }
    for (const char* t : kJsonBad) {
        json::Value v; std::string err;
        if (json::Parse(t, v, err))
            f.Fail(std::string("selfcheck: invalid corpus accepted: ") + t, t);
        else if (err.empty())
            f.Fail("selfcheck: rejection without message", t);
    }
    {
        json::Value v; std::string err;
        if (!json::Parse(DeepNest(30), v, err))
            f.Fail("selfcheck: 30-level nesting should parse", DeepNest(30));
    }
    {
        json::Value v; std::string err;
        if (json::Parse(DeepNest(40), v, err))
            f.Fail("selfcheck: 40-level nesting should be rejected (depth limit)", DeepNest(40));
    }

    std::vector<std::string> corpus;
    for (const char* t : kJsonOk) corpus.push_back(t);

    for (long long i = 0; i < rounds && !f.muted; ++i) {
        f.round = (int)i;
        std::string text;
        switch (r.Range(4)) {
        case 0: {   // 纯随机字节
            const size_t n = r.Range(96);
            for (size_t k = 0; k < n; ++k) text += (char)r.Byte();
            break;
        }
        case 1: text = corpus[r.Range(corpus.size())]; break;                 // 干净基线
        case 2: text = MutateText(r, corpus[r.Range(corpus.size())]); break;  // 变异
        case 3: {   // 双片段拼接
            text = corpus[r.Range(corpus.size())];
            text.insert(r.Range(text.size() + 1), corpus[r.Range(corpus.size())]);
            break;
        }
        }
        CheckJsonText(f, text);
    }
}

// ============================================================
// 目标 2：配置加载（已知键成功 / 未知键报错 / 数值越界拒绝）
// ============================================================

struct CfgCase { const char* text; bool ok; };

const CfgCase kCfgOracle[] = {
    {"{\"fields\":{\"board.serial\":{\"strategy\":\"consensus\"}}}", true},
    {"{\"fields\":{\"disk.*\":{\"strategy\":\"merge_list\",\"weight\":3}}}", true},
    {"{\"fields\":{\"nope\":{\"strategy\":\"consensus\"}}}", false},
    {"{\"fields\":{\"board.seria\":{\"strategy\":\"consensus\"}}}", false},
    {"{\"fields\":{\"cpu.id\":{\"strategy\":\"magic\"}}}", false},
    {"{\"execution\":{\"max_workers\":8}}", true},
    {"{\"execution\":{\"max_workers\":0}}", true},      // 非正数沿用自动档
    {"{\"execution\":{\"max_workers\":-5}}", true},
    {"{\"execution\":{\"max_workers\":257}}", false},   // 超出 1..256
    {"{\"execution\":{\"max_workers\":1e30}}", false},  // 有限但超出可转域
    {"{\"execution\":{\"max_workers\":1e999}}", false}, // 解析层即拒绝（非有限）
    {"{\"execution\":{\"per_task_timeout_ms\":1e30}}", false},
    {"{\"fields\":{\"cpu.id\":{\"weight\":1e30}}}", false},
    {"{\"channels\":{\"wmi\":{\"priority\":1e30,\"tpm_probe\":0}}}", false},
    {"{\"channels\":{\"wmi\":{\"priority\":7,\"tpm_probe\":1}}}", true},
};

const char* kKnownFieldNames[] = {
    "board.serial", "bios.release_date", "cpu.id", "disk.serial",
    "memory.size", "gpu.uuid", "sys.uuid",
};
const char* kKnownWildcards[] = { "disk.*", "memory.*", "cpu.*", "board.*" };
const char* kStrategies[] = {
    "first_by_priority", "consensus", "merge_list", "consensus_aligned",
};

void FuzzConfig(Fuzz& f, Rng& r, long long rounds) {
    // oracle 自检
    for (const CfgCase& c : kCfgOracle) {
        f.cases++;
        HwfpConfig cfg;
        std::string err;
        const bool ok = cfg.LoadFromText(c.text, err);
        if (ok != c.ok)
            f.Fail(std::string("selfcheck: expect ") + (c.ok ? "ok" : "reject") +
                   " got " + (ok ? "ok" : "reject") + " err=" + Clip(err), c.text);
        else if (!ok && err.empty())
            f.Fail("selfcheck: rejection without message", c.text);
        else if (ok && cfg.workers > 256)
            f.Fail("selfcheck: loaded workers out of range", c.text);
    }

    for (long long i = 0; i < rounds && !f.muted; ++i) {
        f.round = (int)i;
        std::string text;
        if (r.Range(3) == 0) {
            // 随机字节：只要求不崩溃、失败必有错误信息
            const size_t n = r.Range(128);
            for (size_t k = 0; k < n; ++k) text += (char)r.Byte();
            HwfpConfig cfg;
            std::string err;
            f.cases++;
            if (!cfg.LoadFromText(text, err) && err.empty())
                f.Fail("reject without message", text);
            continue;
        }
        // 结构化：字段条目取已知池 → 必成功；掺入未知键/坏策略 → 必失败
        bool expect_ok = true;
        std::string entries;
        const int n_known = 1 + (int)r.Range(3);
        for (int k = 0; k < n_known; ++k) {
            std::string key = (r.Range(2) == 0)
                ? kKnownFieldNames[r.Range(sizeof kKnownFieldNames / sizeof(char*))]
                : kKnownWildcards[r.Range(sizeof kKnownWildcards / sizeof(char*))];
            std::string st = kStrategies[r.Range(sizeof kStrategies / sizeof(char*))];
            if (!entries.empty()) entries += ",";
            entries += "\"" + key + "\":{\"strategy\":\"" + st +
                       "\",\"weight\":" + std::to_string((int)r.Range(40)) + "}";
        }
        if (r.Range(100) < 45) {   // 掺一个未知键（策略合法 → 失败原因必须是字段名）
            expect_ok = false;
            if (!entries.empty()) entries += ",";
            entries += "\"nope." + std::to_string(r.Range(1000)) +
                       "\":{\"strategy\":\"consensus\"}";
        } else if (r.Range(100) < 25) {   // 掺一个坏策略（键合法）
            expect_ok = false;
            if (!entries.empty()) entries += ",";
            entries += "\"" +
                std::string(kKnownFieldNames[r.Range(sizeof kKnownFieldNames / sizeof(char*))]) +
                "\":{\"strategy\":\"nope_" + std::to_string(r.Range(100)) + "\"}";
        }
        text = "{\"fields\":{" + entries + "}}";
        HwfpConfig cfg;
        std::string err;
        f.cases++;
        const bool ok = cfg.LoadFromText(text, err);
        if (ok != expect_ok)
            f.Fail(std::string("expect ") + (expect_ok ? "ok" : "reject") +
                   " got " + (ok ? "ok" : "reject") + " err=" + Clip(err), text);
        else if (!ok && err.empty())
            f.Fail("reject without message", text);
    }
}

// ============================================================
// 目标 3：SMBIOS 表解析
// ============================================================

// fmt[0]=type, fmt[1]=len(回填)，下标=规范偏移；字符串区每串自带 \0，区尾终止 \0
std::vector<uint8_t> SmbStruct(std::vector<uint8_t> fmt,
                               const std::vector<std::string>& strings) {
    fmt[1] = (uint8_t)fmt.size();
    for (const auto& s : strings) {
        fmt.insert(fmt.end(), s.begin(), s.end());
        fmt.push_back(0);
    }
    fmt.push_back(0);
    return fmt;
}

std::vector<uint8_t> SmbBios() {
    std::vector<uint8_t> f(0x09, 0);
    f[0x00] = 0; f[0x04] = 1; f[0x05] = 2; f[0x08] = 3;
    return SmbStruct(f, { "TestBIOS Inc", "1.02", "07/25/2024" });
}
std::vector<uint8_t> SmbSys() {
    std::vector<uint8_t> f(0x1B, 0);
    f[0x00] = 1; f[0x04] = 1; f[0x05] = 2; f[0x06] = 3; f[0x07] = 4;
    for (int i = 0; i < 16; ++i) f[0x08 + i] = (uint8_t)(0x10 + i);
    f[0x19] = 5; f[0x1A] = 6;
    return SmbStruct(f, { "TestMfr", "TestProduct", "1.0", "SER-1234", "SKU-9", "Fam-X" });
}
std::vector<uint8_t> SmbBoard() {
    std::vector<uint8_t> f(0x08, 0);
    f[0x00] = 2; f[0x04] = 1; f[0x05] = 2; f[0x06] = 3; f[0x07] = 4;
    return SmbStruct(f, { "BoardMfr", "BoardModel", "v1", "BRD-5678" });
}
std::vector<uint8_t> SmbCpu() {
    std::vector<uint8_t> f(0x12, 0);
    f[0x00] = 4; f[0x07] = 1; f[0x10] = 2;
    const uint8_t id[8] = { 0x00, 0xF4, 0x0B, 0x00, 0xFF, 0xFB, 0x8B, 0x17 };
    for (int i = 0; i < 8; ++i) f[0x08 + i] = id[i];
    return SmbStruct(f, { "AMD", "Test CPU Model" });
}
std::vector<uint8_t> SmbMem() {
    std::vector<uint8_t> f(0x1B, 0);
    f[0x00] = 17; f[0x0C] = 0x00; f[0x0D] = 0x40;   // 16384 MB
    f[0x10] = 1; f[0x17] = 2; f[0x18] = 3; f[0x1A] = 4;
    return SmbStruct(f, { "DIMMA2", "Kingstop", "MSER-01", "PART-ABC" });
}

std::vector<uint8_t> SmbTable(const std::vector<std::vector<uint8_t>>& structs) {
    std::vector<uint8_t> v{ 0, 3, 7, 1, 0, 0, 0, 0 };
    for (const auto& s : structs) v.insert(v.end(), s.begin(), s.end());
    const uint32_t n = (uint32_t)(v.size() - 8);
    v[4] = (uint8_t)n; v[5] = (uint8_t)(n >> 8);
    v[6] = (uint8_t)(n >> 16); v[7] = (uint8_t)(n >> 24);
    return v;
}

// 任意输入解析成功后的输出有界性（越界读/失控计数的直接信号）
void CheckSmbiosBounds(Fuzz& f, const SmbiosData& d, size_t len) {
    const std::string* strs[] = {
        &d.bios_vendor, &d.bios_version, &d.bios_release_date, &d.bios_serial,
        &d.sys_manufacturer, &d.sys_product, &d.sys_version, &d.sys_serial,
        &d.sys_uuid_hex, &d.sys_sku, &d.sys_family,
        &d.board_manufacturer, &d.board_product, &d.board_version, &d.board_serial,
    };
    for (const std::string* s : strs)
        if (s->size() > len)
            f.Fail("scalar string longer than input (out-of-bounds read)", "");
    for (const SmbiosCpu& c : d.cpus) {
        if (c.manufacturer.size() > len || c.version.size() > len || c.id_hex.size() > len)
            f.Fail("cpu string longer than input (out-of-bounds read)", "");
    }
    for (const SmbiosMemory& m : d.mems) {
        if (m.locator.size() > len || m.manufacturer.size() > len ||
            m.serial.size() > len || m.part.size() > len)
            f.Fail("memory string longer than input (out-of-bounds read)", "");
    }
    if (d.cpus.size() > len / 4 + 8 || d.mems.size() > len / 4 + 8)
        f.Fail("implausible instance count for input size", "");
}

void FuzzSmbios(Fuzz& f, Rng& r, long long rounds) {
    // oracle 自检：合法表必须精确还原（含 Type17 偏移与 Type4 去重口径）
    {
        const std::vector<uint8_t> buf = SmbTable({ SmbBios(), SmbSys(), SmbBoard(), SmbCpu(), SmbMem() });
        SmbiosData d; std::string err;
        f.cases++;
        if (!ParseSmbios(buf.data(), buf.size(), d, err)) {
            f.Fail("selfcheck: valid table rejected", "");
        } else {
            if (d.board_serial != "BRD-5678" || d.sys_serial != "SER-1234" ||
                d.bios_vendor != "TestBIOS Inc" || d.cpus.size() != 1 ||
                d.cpus[0].id_hex != "00F40B00FFFB8B17" ||
                d.mems.size() != 1 || d.mems[0].locator != "DIMMA2" ||
                d.mems[0].size_mb != 16384 || d.mems[0].part != "PART-ABC")
                f.Fail("selfcheck: valid table fields mismatch", "");
        }
    }

    const std::vector<uint8_t> full = SmbTable({ SmbBios(), SmbSys(), SmbBoard(), SmbCpu(), SmbMem() });
    const std::vector<uint8_t> small = SmbTable({ SmbBoard(), SmbMem() });

    for (long long i = 0; i < rounds && !f.muted; ++i) {
        f.round = (int)i;
        f.cases++;
        if (i % 16 == 0) {
            // 全前缀截断扫描：0..N 每个长度都必须安全
            for (size_t len = 0; len <= small.size(); ++len) {
                SmbiosData d; std::string err;
                ParseSmbios(small.data(), len, d, err);
            }
            SmbiosData d; std::string err;
            ParseSmbios(nullptr, 0, d, err);
            continue;
        }
        if (r.Range(100) < 20) {
            // 纯随机噪声缓冲
            const size_t n = r.Range(1024);
            std::vector<uint8_t> noise(n);
            for (size_t k = 0; k < n; ++k) noise[k] = (uint8_t)r.Byte();
            SmbiosData d; std::string err;
            const bool ok = ParseSmbios(noise.data(), noise.size(), d, err);
            if (ok) CheckSmbiosBounds(f, d, noise.size());
            continue;
        }
        // 合法表逐字节变异
        const std::vector<uint8_t> mutated = MutateBytes(r, full, 5);
        SmbiosData d; std::string err;
        const bool ok = ParseSmbios(mutated.data(), mutated.size(), d, err);
        if (ok) CheckSmbiosBounds(f, d, mutated.size());
    }
}

// ============================================================
// 目标 4：EDID 头解析
// ============================================================

std::vector<uint8_t> MakeEdid(uint16_t man, uint16_t pid, uint32_t serial) {
    std::vector<uint8_t> e(128, 0);
    const uint8_t hdr[8] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    std::memcpy(e.data(), hdr, 8);
    e[8] = (uint8_t)(man >> 8); e[9] = (uint8_t)(man & 0xFF);
    e[10] = (uint8_t)(pid & 0xFF); e[11] = (uint8_t)(pid >> 8);
    for (int i = 0; i < 4; ++i) e[12 + i] = (uint8_t)(serial >> (8 * i));
    return e;
}

// 厂码输出形态："unk" 或 3 个 [0x41,0x5F] 字符（5bit 码 1..31 → 'A'+码-1）
bool VendorCodeWellFormed(const char v[4]) {
    if (std::memcmp(v, "unk", 4) == 0) return true;
    for (int i = 0; i < 3; ++i) {
        const unsigned char c = (unsigned char)v[i];
        if (c < 0x41 || c > 0x5F) return false;
    }
    return v[3] == '\0';
}

void FuzzEdid(Fuzz& f, Rng& r, long long rounds) {
    // A=1,U=21,S=19 → man=(1<<10)|(21<<5)|19
    const uint16_t kManAUS = (uint16_t)((1 << 10) | (21 << 5) | 19);
    // oracle 自检
    {
        const std::vector<uint8_t> e = MakeEdid(kManAUS, 0xA325, 0x01010101u);
        EdidInfo info;
        f.cases++;
        if (!ParseEdid(e.data(), e.size(), info))
            f.Fail("selfcheck: valid EDID rejected", "");
        else if (std::memcmp(info.vendor_code, "AUS", 4) != 0 ||
                 info.product_id != 0xA325 || info.serial_int != 0x01010101u)
            f.Fail("selfcheck: EDID fields mismatch", "");
    }

    const std::vector<uint8_t> base = MakeEdid(kManAUS, 0xA325, 0x01010101u);
    for (long long i = 0; i < rounds && !f.muted; ++i) {
        f.round = (int)i;
        f.cases++;
        if (i % 16 == 0) {
            for (size_t len = 0; len <= 128; ++len) {
                EdidInfo info;
                ParseEdid(base.data(), len, info);
            }
            EdidInfo info;
            ParseEdid(nullptr, 0, info);
            continue;
        }
        std::vector<uint8_t> bytes;
        if (r.Range(100) < 30) {
            const size_t n = r.Range(160);
            bytes.resize(n);
            for (size_t k = 0; k < n; ++k) bytes[k] = (uint8_t)r.Byte();
        } else {
            bytes = MutateBytes(r, base, 6);
        }
        EdidInfo info;
        if (ParseEdid(bytes.data(), bytes.size(), info) &&
            !VendorCodeWellFormed(info.vendor_code))
            f.Fail("vendor code malformed on successful parse", "");
    }
}

// ============================================================
// 目标 5：nvidia-smi CSV 解析（差异测试：独立重实现行切分对账）
// ============================================================

bool StrictUuid(const std::string& s) {   // oracle 基准：前缀 + 8-4-4-4-12 hex
    if (s.size() != 40) return false;
    if (s.compare(0, 4, "GPU-") != 0 && s.compare(0, 4, "MIG-") != 0) return false;
    static const int L[5] = { 8, 4, 4, 4, 12 };
    size_t i = 4;
    for (int g = 0; g < 5; ++g) {
        for (int k = 0; k < L[g]; ++k, ++i) {
            const char c = s[i];
            const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                             (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        if (g < 4) { if (s[i] != '-') return false; ++i; }
    }
    return true;
}

std::string TrimOracle(const std::string& s) {
    const char* ws = " \t\r\n";
    const size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos) return {};
    const size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
}

std::vector<native_util::NvidiaGpu> CsvOracle(const std::string& text) {
    std::vector<native_util::NvidiaGpu> out;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t eol = text.find('\n', pos);
        const std::string line = TrimOracle(text.substr(
            pos, eol == std::string::npos ? std::string::npos : eol - pos));
        pos = (eol == std::string::npos) ? text.size() + 1 : eol + 1;
        if (line.empty()) continue;
        const size_t first = line.find(',');
        if (first == std::string::npos) continue;
        const size_t last = line.rfind(',');
        if (last == first) continue;
        const std::string idx = TrimOracle(line.substr(0, first));
        const std::string uuid = TrimOracle(line.substr(last + 1));
        const std::string name = TrimOracle(line.substr(first + 1, last - first - 1));
        if (idx.empty() || idx.find_first_not_of("0123456789") != std::string::npos)
            continue;
        if (!StrictUuid(uuid)) continue;
        out.push_back(native_util::NvidiaGpu{ idx, name, uuid });
    }
    return out;
}

void FuzzNvidiaCsv(Fuzz& f, Rng& r, long long rounds) {
    const char* kClean =
        "0, NVIDIA GeForce RTX 3060, GPU-01234567-89ab-cdef-0123-456789abcdef\n"
        "1, Some, Name With, Commas, MIG-12345678-9abc-def0-1234-56789abcdef0\n"
        "2, No Uuid Card, [N/A]\n"
        "\n"
        "line without commas\n"
        "x, non numeric index, GPU-01234567-89ab-cdef-0123-456789abcdef\n";
    // oracle 自检：干净文本必须精确解析出 2 行，name 保留内嵌逗号
    {
        f.cases++;
        const auto got = native_util::ParseNvidiaSmiUuidCsv(kClean);
        const auto want = CsvOracle(kClean);
        if (got.size() != 2 || got.size() != want.size())
            f.Fail("selfcheck: clean csv count mismatch", kClean);
        else if (got[1].name != "Some, Name With, Commas")
            f.Fail("selfcheck: embedded-comma name mangled", kClean);
    }

    const std::string clean(kClean);
    for (long long i = 0; i < rounds && !f.muted; ++i) {
        f.round = (int)i;
        std::string text;
        if (r.Range(100) < 25) {
            const size_t n = r.Range(256);
            for (size_t k = 0; k < n; ++k) text += (char)r.Byte();
        } else {
            text = MutateText(r, clean);
        }
        f.cases++;
        const auto got = native_util::ParseNvidiaSmiUuidCsv(text);
        const auto want = CsvOracle(text);
        bool same = got.size() == want.size();
        for (size_t k = 0; same && k < got.size(); ++k)
            same = got[k].index == want[k].index && got[k].name == want[k].name &&
                   got[k].uuid == want[k].uuid;
        if (!same) f.Fail("csv parse diverges from oracle", text);
    }

    // UUID 形态判定：与 StrictUuid 全量等价
    static const char kAlpha[] = "GPU-MIG-0123456789abcdefABCDEF-[] xN/A/";
    for (long long i = 0; i < rounds && !f.muted; ++i) {
        f.round = (int)i;
        std::string s;
        const size_t n = r.Range(48);
        for (size_t k = 0; k < n; ++k) s += kAlpha[r.Range(sizeof kAlpha - 1)];
        f.cases++;
        if (native_util::IsNvidiaGpuUuid(s) != StrictUuid(s))
            f.Fail("uuid verdict diverges from strict oracle", s);
    }
}

// ============================================================
// 目标 6：归并 + 指纹 + 报告往返
// ============================================================

bool IsHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

void CheckMergedInvariants(Fuzz& f, const MergedResults& merged) {
    for (const auto& kv : merged) {
        if (kv.second.empty())
            f.Fail("merged key with empty instance list", "");
        for (size_t i = 0; i < kv.second.size(); ++i) {
            const FieldResult& e = kv.second[i];
            if (e.index != (int)i)
                f.Fail("instance index not sequential", "");
            if (e.ok && e.value.empty())
                f.Fail("ok entry with empty value", "");
            if (!e.ok && !e.value.empty())
                f.Fail("failed entry with non-empty value", "");
            if (e.placeholder && e.ok)
                f.Fail("placeholder entry marked ok", "");
            if (e.candidates.empty())
                f.Fail("entry without candidates", "");
        }
    }
}

void FuzzPipeline(Fuzz& f, Rng& r, long long rounds) {
    static const char* kChannels[] = { "smbios", "wmi", "native", "registry" };
    static const char* kValues[] = {
        "", " ", "0", "None", "To be filled by O.E.M.", "abc", "ABC-123",
        "中文值", "0011223344556677", "GPU-01234567-89ab-cdef-0123-456789abcdef",
        "AABBCCDDEE01", "178BFBFF00B40F40", "26200", "00000000",
    };
    static const char* kInstKeys[] = { "", "0", "1", "2", "10", "a" };

    for (long long i = 0; i < rounds && !f.muted; ++i) {
        f.round = (int)i;
        // 随机候选集
        std::map<FieldKey, std::vector<Candidate>> by_key;
        const int n_keys = 1 + (int)r.Range(6);
        for (int k = 0; k < n_keys; ++k) {
            const FieldKey key = (FieldKey)r.Range((size_t)FieldKey::kFieldCount);
            const int n_cand = 1 + (int)r.Range(4);
            for (int c = 0; c < n_cand; ++c) {
                Candidate cd;
                cd.channel = kChannels[r.Range(4)];
                cd.value = kValues[r.Range(sizeof kValues / sizeof(char*))];
                cd.note = r.Range(100) < 30 ? "note" : "";
                cd.ok = r.Range(100) < 80;
                cd.instance_key = kInstKeys[r.Range(sizeof kInstKeys / sizeof(char*))];
                by_key[key].push_back(cd);
            }
        }
        MergedResults merged = MergeAll(by_key);
        CheckMergedInvariants(f, merged);

        f.cases++;
        const fp::FingerprintOutput fp1 = fp::ComputeFingerprint(merged);
        if (!IsHex64(fp1.master))
            f.Fail("master fingerprint not 64 uppercase hex", "");
        for (const auto& g : fp1.sub)
            if (!IsHex64(g.second))
                f.Fail("sub fingerprint not 64 uppercase hex", "");
        const fp::FingerprintOutput fp2 = fp::ComputeFingerprint(merged);
        if (fp2.master != fp1.master)
            f.Fail("fingerprint not deterministic", "");

        const double self = fp::Similarity(fp1, fp1);
        const double expect_self = fp1.sub.empty() ? 0.0 : 1.0;
        if (self < expect_self - 1e-9 || self > expect_self + 1e-9)
            f.Fail("self similarity not 1.0", "");
        if (self < 0.0 || self > 1.0)
            f.Fail("similarity out of [0,1]", "");

        // 报告往返：Build → Parse → 重算 == 原指纹（T8 完整性链路的模糊化）
        if (i % 8 == 0) {
            CollectorManager::RunResult rr;
            rr.merged = merged;
            rr.instances = (int)merged.size();
            rr.ms = 1.0;
            const std::string text = report::BuildJson(rr, fp1, "0.0.0-fuzz");
            MergedResults back;
            fp::FingerprintOutput old_fp;
            std::string err;
            if (!report::ParseReport(text, back, old_fp, err))
                f.Fail("report roundtrip parse failed: " + Clip(err), Clip(text, 400));
            else {
                const auto recomputed = fp::ComputeFingerprint(back);
                if (recomputed.master != fp1.master)
                    f.Fail("report roundtrip master mismatch", Clip(text, 400));
            }
        }
    }
}

// ============================================================
// 目标 7：license（签发 → 变异 → 校验）
// oracle：变异后仍判 valid 的授权，其语义字段必须与原件逐字段一致
// （防"改了字段还能过"）；随机文本不崩溃；随机串 nonce/绑定行为受控
// ============================================================

struct LicenseFixture {
    std::string priv, pub;
    lic::LicenseData base;            // 绑定机器 A 的授权
    fp::FingerprintOutput machine_a;
    std::string text;                 // base 的签发产物
    bool ready = false;

    LicenseFixture() {
        ready = lic::GenerateKeyPair(priv, pub);
        if (!ready) return;
        base.licensee = "fuzz licensee";
        base.issued_at = "2026-09-18";
        base.expires_at = "2099-01-01";
        base.fingerprint = std::string(64, 'A');
        base.sub["board"] = std::string(64, 'B');
        base.sub["cpu"] = std::string(64, 'C');
        base.features["seats"] = "5";
        base.nonce = "0123456789ABCDEF0123456789ABCDEF";
        machine_a.master = base.fingerprint;
        machine_a.sub = base.sub;
        std::string err;
        ready = lic::Issue(base, priv, text, err);
    }
};

bool SameFields(const lic::LicenseData& a, const lic::LicenseData& b) {
    return a.licensee == b.licensee && a.issued_at == b.issued_at &&
           a.expires_at == b.expires_at && a.fingerprint == b.fingerprint &&
           a.sub == b.sub && a.features == b.features && a.nonce == b.nonce;
}

void FuzzLicense(Fuzz& f, Rng& r, long long rounds) {
    LicenseFixture fx;
    if (!fx.ready) {
        f.Fail("selfcheck: keygen/issue failed", "");
        return;
    }
    // oracle 自检：干净授权必须有效
    {
        lic::LicenseCheck res;
        std::string err;
        f.cases++;
        if (!lic::Check(fx.text, fx.pub, &fx.machine_a, 0.85, res, err) || !res.valid())
            f.Fail("selfcheck: valid license rejected", Clip(fx.text, 200));
    }

    for (long long i = 0; i < rounds && !f.muted; ++i) {
        f.round = (int)i;
        std::string text;
        if (r.Range(100) < 30) {
            // 随机文本：只要求不崩溃
            const size_t n = r.Range(256);
            for (size_t k = 0; k < n; ++k) text += (char)r.Byte();
            lic::LicenseCheck res;
            std::string err;
            f.cases++;
            lic::Check(text, fx.pub, nullptr, 0.85, res, err);
            continue;
        }
        text = MutateText(r, fx.text);
        lic::LicenseCheck res;
        std::string err;
        f.cases++;
        lic::Check(text, fx.pub, &fx.machine_a, 0.85, res, err);
        if (res.valid()) {
            // 判 valid ⇒ 语义字段必须与原件一致（改了任何载荷字段都该验签失败）
            lic::LicenseData parsed;
            if (!lic::ParseLicense(text, parsed, err) || !SameFields(parsed, fx.base))
                f.Fail("mutated license accepted with altered fields", Clip(text, 200));
        }
    }

    // 直改单字节的真篡改：载荷任一字段变化后 valid 必须转 false
    const char* fields[] = { "fuzz licensee", "seats", "2099-01-01" };
    for (long long i = 0; i < rounds && !f.muted; ++i) {
        f.round = (int)i;
        std::string t = fx.text;
        const std::string from = fields[r.Range(3)];
        const size_t p = t.find(from);
        if (p == std::string::npos) continue;
        t[p] = (char)(t[p] == 'X' ? 'Y' : 'X');
        lic::LicenseCheck res;
        std::string err;
        f.cases++;
        lic::Check(t, fx.pub, &fx.machine_a, 0.85, res, err);
        if (res.valid()) {
            lic::LicenseData parsed;
            if (!lic::ParseLicense(t, parsed, err) || !SameFields(parsed, fx.base))
                f.Fail("tampered field still valid", Clip(t, 200));
        }
    }
}

} // namespace fz

int main(int argc, char** argv) {
    const long long rounds_def = 200000;
    long long rounds = rounds_def;
    if (argc > 1) rounds = std::atoll(argv[1]);
    if (rounds <= 0) rounds = rounds_def;
    uint64_t seed = 0xC0FFEE1234567890ull;
    if (argc > 2) seed = std::strtoull(argv[2], nullptr, 0);
    const long long per_target = rounds / 7;   // 七个目标均分

    std::printf("[fuzz] rounds=%lld per-target=%lld seed=0x%llX\n",
                rounds, per_target, (unsigned long long)seed);

    struct Target { const char* name; void (*fn)(fz::Fuzz&, fz::Rng&, long long); };
    const Target targets[] = {
        { "json",      fz::FuzzJson },
        { "config",    fz::FuzzConfig },
        { "smbios",    fz::FuzzSmbios },
        { "edid",      fz::FuzzEdid },
        { "nvidiasmi", fz::FuzzNvidiaCsv },
        { "pipeline",  fz::FuzzPipeline },
        { "license",   fz::FuzzLicense },
    };

    long long total_fail = 0;
    for (size_t ti = 0; ti < sizeof targets / sizeof targets[0]; ++ti) {
        const Target& t = targets[ti];
        fz::Fuzz f;
        f.target = t.name;
        f.seed = seed;
        fz::Rng r(seed ^ (0x9E3779B97F4A7C15ull * (uint64_t)(ti + 1)));   // 每目标独立序列
        t.fn(f, r, per_target);
        std::printf("[fuzz] %-10s cases=%-8lld failures=%lld\n",
                    t.name, f.cases, f.failures);
        total_fail += f.failures;
    }
    std::printf("[fuzz] total failures: %lld -> %s\n", total_fail,
                total_fail ? "FAIL" : "OK");
    return total_fail ? 1 : 0;
}
