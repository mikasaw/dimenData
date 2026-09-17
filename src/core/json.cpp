#include "core/json.h"
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace json {
namespace {

struct Parser {
    const std::string& s;
    size_t pos = 0;
    std::string err;
    int line = 1, col = 1;

    explicit Parser(const std::string& text) : s(text) {}

    void Adv() {
        if (pos < s.size()) {
            if (s[pos] == '\n') { ++line; col = 1; } else { ++col; }
            ++pos;
        }
    }
    void SkipWs() {
        while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' ||
                                  s[pos] == '\r' || s[pos] == '\n'))
            Adv();
    }
    bool Fail(const std::string& what) {
        if (err.empty()) {
            std::ostringstream os;
            os << line << ":" << col << " " << what;
            err = os.str();
        }
        return false;
    }

    bool ParseValue(Value& out, int depth) {
        if (depth > 32) return Fail("嵌套过深");
        SkipWs();
        if (pos >= s.size()) return Fail("输入提前结束");
        const char c = s[pos];
        if (c == '{') return ParseObj(out, depth);
        if (c == '[') return ParseArr(out, depth);
        if (c == '"') { out.type = Value::Str; return ParseStr(out.str); }
        if (c == 't' || c == 'f') return ParseBool(out);
        if (c == 'n') return ParseNull(out);
        return ParseNum(out);
    }

    bool Expect(char c) {
        SkipWs();
        if (pos >= s.size() || s[pos] != c) return Fail(std::string("期望 '") + c + "'");
        Adv();
        return true;
    }

    bool ParseObj(Value& out, int depth) {
        out.type = Value::Obj;
        Adv();  // {
        SkipWs();
        if (pos < s.size() && s[pos] == '}') { Adv(); return true; }
        for (;;) {
            SkipWs();
            if (pos >= s.size() || s[pos] != '"') return Fail("对象键应为字符串");
            std::string key;
            if (!ParseStr(key)) return false;
            if (!Expect(':')) return false;
            Value v;
            if (!ParseValue(v, depth + 1)) return false;
            out.obj[key] = std::move(v);
            SkipWs();
            if (pos < s.size() && s[pos] == ',') { Adv(); continue; }
            if (pos < s.size() && s[pos] == '}') { Adv(); return true; }
            return Fail("对象应为 ',' 或 '}'");
        }
    }

    bool ParseArr(Value& out, int depth) {
        out.type = Value::Arr;
        Adv();  // [
        SkipWs();
        if (pos < s.size() && s[pos] == ']') { Adv(); return true; }
        for (;;) {
            Value v;
            if (!ParseValue(v, depth + 1)) return false;
            out.arr.push_back(std::move(v));
            SkipWs();
            if (pos < s.size() && s[pos] == ',') { Adv(); continue; }
            if (pos < s.size() && s[pos] == ']') { Adv(); return true; }
            return Fail("数组应为 ',' 或 ']'");
        }
    }

    bool ParseStr(std::string& out) {
        Adv();  // 开引号
        out.clear();
        for (; pos < s.size(); Adv()) {
            const char c = s[pos];
            if (c == '"') { Adv(); return true; }
            if (c == '\\') {
                Adv();
                if (pos >= s.size()) return Fail("转义符后提前结束");
                const char e = s[pos];
                switch (e) {
                case '"':  out += '"'; break;
                case '\\': out += '\\'; break;
                case '/':  out += '/'; break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'u': {
                    // \uXXXX：仅支持 BMP 直转 UTF-8；代理对输出占位符（本项目不产生）
                    if (pos + 4 >= s.size()) return Fail("\\u 后位数不足");
                    unsigned code = 0;
                    for (int i = 1; i <= 4; ++i) {
                        const char h = s[pos + i];
                        code <<= 4;
                        if (h >= '0' && h <= '9') code |= (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') code |= (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') code |= (unsigned)(h - 'A' + 10);
                        else return Fail("\\u 含非法十六进制");
                    }
                    pos += 4;
                    if (code < 0x80) {
                        out += (char)code;
                    } else if (code < 0x800) {
                        out += (char)(0xC0 | (code >> 6));
                        out += (char)(0x80 | (code & 0x3F));
                    } else {
                        out += (char)(0xE0 | (code >> 12));
                        out += (char)(0x80 | ((code >> 6) & 0x3F));
                        out += (char)(0x80 | (code & 0x3F));
                    }
                    break;
                }
                default: return Fail("非法转义字符");
                }
                continue;
            }
            out += c;
        }
        return Fail("字符串未闭合");
    }

    bool ParseBool(Value& out) {
        if (s.compare(pos, 4, "true") == 0) {
            pos += 4; out.type = Value::Bool; out.boolean = true; return true;
        }
        if (s.compare(pos, 5, "false") == 0) {
            pos += 5; out.type = Value::Bool; out.boolean = false; return true;
        }
        return Fail("非法字面量");
    }

    bool ParseNull(Value& out) {
        if (s.compare(pos, 4, "null") == 0) {
            pos += 4; out.type = Value::Null; return true;
        }
        return Fail("非法字面量");
    }

    bool ParseNum(Value& out) {
        // 严格 JSON 数字文法: -? int (frac)? (exp)?——不接受 "-", "1.2.3", "1e" 等残缺形式
        const size_t start = pos;
        if (pos < s.size() && s[pos] == '-') Adv();
        size_t digits = 0;
        while (pos < s.size() && std::isdigit((unsigned char)s[pos])) { Adv(); ++digits; }
        if (digits == 0) return Fail("非法数值：整数部分缺数字");
        if (pos < s.size() && s[pos] == '.') {
            Adv();
            size_t fd = 0;
            while (pos < s.size() && std::isdigit((unsigned char)s[pos])) { Adv(); ++fd; }
            if (fd == 0) return Fail("非法数值：小数点后缺数字");
        }
        if (pos < s.size() && (s[pos] == 'e' || s[pos] == 'E')) {
            Adv();
            if (pos < s.size() && (s[pos] == '+' || s[pos] == '-')) Adv();
            size_t ed = 0;
            while (pos < s.size() && std::isdigit((unsigned char)s[pos])) { Adv(); ++ed; }
            if (ed == 0) return Fail("非法数值：指数缺数字");
        }
        out.type = Value::Num;
        out.number = std::strtod(s.substr(start, pos - start).c_str(), nullptr);
        // 溢出（如 1e999）得 inf：NumberToString 会产出 "inf"，自家解析器不认——
        // 数值统一按 double 承载，非有限值在解析层直接拒绝
        if (!std::isfinite(out.number)) return Fail("数值超出可表示范围");
        return true;
    }
};

} // namespace

bool Value::GetStr(const char* key, std::string& out) const {
    auto it = obj.find(key);
    if (it == obj.end() || !it->second.IsStr()) return false;
    out = it->second.str;
    return true;
}
bool Value::GetNum(const char* key, double& out) const {
    auto it = obj.find(key);
    if (it == obj.end() || !it->second.IsNum()) return false;
    out = it->second.number;
    return true;
}
bool Value::GetBool(const char* key, bool& out) const {
    auto it = obj.find(key);
    if (it == obj.end() || !it->second.IsBool()) return false;
    out = it->second.boolean;
    return true;
}

bool Parse(const std::string& text, Value& out, std::string& err) {
    Parser p(text);
    if (!p.ParseValue(out, 0)) { err = p.err; return false; }
    p.SkipWs();
    if (p.pos != text.size()) {
        p.Fail("结尾存在多余内容");   // 与其余错误一致带 行:列
        err = p.err;
        return false;
    }
    return true;
}

std::string Escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof b, "\\u%04X", c);
                out += b;
            } else {
                out += (char)c;   // UTF-8 字节透传
            }
        }
    }
    return out;
}

std::string NumberToString(double v) {
    if (std::floor(v) == v && std::fabs(v) < 1e15) {
        char b[32];
        std::snprintf(b, sizeof b, "%lld", (long long)v);
        return b;
    }
    // 非整数：17 位有效数字保证 double 精确往返（文本自稳定）。
    // 曾用 %.6g：1.23457e+06 这类指数形态重解析后落在整数分支，
    // 同一数值两种文本（fuzz 首轮捕获）
    char b[40];
    std::snprintf(b, sizeof b, "%.17g", v);
    return b;
}

} // namespace json
