// ============================================================
// 极简 JSON（零依赖）：解析 + 序列化转义，供配置读取与报告输出共用
// 支持对象/数组/字符串/数值/布尔/null；数值统一按 double 携带
// （本项目配置与输出仅用到整型数值，输出时整数值不带小数点）
// ============================================================
#pragma once
#include <map>
#include <string>
#include <vector>

namespace json {

struct Value {
    enum Type { Null, Bool, Num, Str, Arr, Obj };
    Type type = Null;
    bool boolean = false;
    double number = 0;
    std::string str;
    std::vector<Value> arr;
    std::map<std::string, Value> obj;

    bool IsNull() const { return type == Null; }
    bool IsStr()  const { return type == Str; }
    bool IsNum()  const { return type == Num; }
    bool IsBool() const { return type == Bool; }
    bool IsArr()  const { return type == Arr; }
    bool IsObj()  const { return type == Obj; }

    // 便捷取值：键不存在或类型不符返回 false
    bool GetStr(const char* key, std::string& out) const;
    bool GetNum(const char* key, double& out) const;
    bool GetBool(const char* key, bool& out) const;
};

// 解析整个文本；失败返回 false 并写 err（含行:列）
bool Parse(const std::string& text, Value& out, std::string& err);

// 字符串 JSON 转义（含控制字符 \u00XX；UTF-8 字节原样透传）
std::string Escape(const std::string& s);

// 数值序列化：整数值不带小数点
std::string NumberToString(double v);

} // namespace json
