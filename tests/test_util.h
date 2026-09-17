// ============================================================
// 极简单元测试框架（零依赖）
// 用法：
//   TEST(组名, 用例名) { CHECK(cond); CHECK_EQ(a, b); }
//   int main() { return RunAllTests(); }
// ============================================================
#pragma once
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

inline int g_checksFailed = 0;
inline std::string g_currentTest;

inline void RecordFailure(const char* file, int line, const std::string& what) {
    ++g_checksFailed;
    std::printf("  [FAIL] %s:%d  (%s)  %s\n", file, line, g_currentTest.c_str(), what.c_str());
}

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) RecordFailure(__FILE__, __LINE__, "CHECK(" #cond ")");   \
    } while (0)

// 前置断言：失败则中止当前用例（后续 CHECK 依赖此前提时使用）
#define ASSERT(cond)                                                         \
    do {                                                                     \
        if (!(cond)) {                                                       \
            RecordFailure(__FILE__, __LINE__, "ASSERT(" #cond ")");          \
            return;                                                          \
        }                                                                    \
    } while (0)

#define CHECK_EQ(a, b)                                                       \
    do {                                                                     \
        auto&& _va = (a);                                                    \
        auto&& _vb = (b);                                                    \
        if (!(_va == _vb)) {                                                 \
            std::string _d = std::string("CHECK_EQ(" #a ", " #b ")  got: ") + \
                             std::to_string(_va) + " vs " + std::to_string(_vb); \
            RecordFailure(__FILE__, __LINE__, _d);                           \
        }                                                                    \
    } while (0)

// 字符串版本（与数值版重名会歧义，故独立命名）
#define CHECK_STREQ(a, b)                                                    \
    do {                                                                     \
        std::string _va = (a);                                               \
        std::string _vb = (b);                                               \
        if (!(_va == _vb))                                                   \
            RecordFailure(__FILE__, __LINE__,                                \
                          "CHECK_STREQ(" #a ", " #b ")  got: \"" + _va +     \
                          "\" vs \"" + _vb + "\"");                          \
    } while (0)

struct TestCase { const char* group; const char* name; std::function<void()> fn; };
inline std::vector<TestCase>& GetTests() { static std::vector<TestCase> t; return t; }

#define TEST(group, name)                                                    \
    static void test_##group##_##name();                                     \
    static bool s_reg_##group##_##name = []() {                              \
        GetTests().push_back({#group, #name, test_##group##_##name});        \
        return true;                                                         \
    }();                                                                     \
    static void test_##group##_##name()

inline int RunAllTests() {
    int failedCases = 0;
    for (const auto& t : GetTests()) {
        const int before = g_checksFailed;
        g_currentTest = std::string(t.group) + "." + t.name;
        t.fn();
        if (g_checksFailed > before) ++failedCases;
    }
    std::printf("[tests] %zu cases, %d failed, %d failed checks\n",
                GetTests().size(), failedCases, g_checksFailed);
    return failedCases == 0 ? 0 : 1;
}
