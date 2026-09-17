// ============================================================
// hwfp.dll 集成消费者（dlltest 目标）：以隐式链接方式调用全部导出，
// 验证 C ABI 在真实加载场景下可用
// 用法: build.cmd dlltest   （编译 build\hwfp_dll_consumer.exe 并运行）
// ============================================================
#include <windows.h>
#include "dll/hwfp_dll.h"
#include <cstdio>
#include <cstring>
#include <string>

namespace {

int g_failed = 0;

void Check(bool cond, const char* what) {
    if (!cond) {
        ++g_failed;
        std::printf("  [FAIL] %s\n", what);
    } else {
        std::printf("  [ok] %s\n", what);
    }
}

} // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);

    // 1. 版本
    const char* v = Hwfp_Version();
    Check(v && std::strstr(v, "0.1") == v, "Hwfp_Version returns 0.1.x");

    // 2. 采集（真实硬件；输出 JSON 含指纹）
    char* json = nullptr;
    const int rc = Hwfp_Collect(&json);
    Check(rc == 0 && json, "Hwfp_Collect returns 0 with payload");
    Check(json && std::strstr(json, "\"fingerprint\"") != nullptr,
          "collect payload contains fingerprint");
    Check(json && std::strstr(json, "master") != nullptr,
          "collect payload contains master");

    // 3. 配置采集（合法 / 非法配置）
    char* json2 = nullptr;
    Check(Hwfp_CollectWithConfig("{\"execution\":{\"max_workers\":2}}", &json2) == 0 &&
          json2 != nullptr, "Hwfp_CollectWithConfig valid config");
    char* bad = reinterpret_cast<char*>(1);
    Check(Hwfp_CollectWithConfig("not json", &bad) == 2 && bad == nullptr,
          "Hwfp_CollectWithConfig bad config -> 2, out null");
    Check(Hwfp_CollectWithConfig(nullptr, &bad) == 2,
          "Hwfp_CollectWithConfig null -> 2");

    // 4. 授权校验（畸形输入 → 2/5；不触发真实签发链路）
    char* res = reinterpret_cast<char*>(1);
    Check(Hwfp_CheckLicense(nullptr, "x", 0.85, &res) == 2 && res == nullptr,
          "Hwfp_CheckLicense null license -> 2");
    Check(Hwfp_CheckLicense("{}", "not-a-key", 0.85, &res) == 5 && res != nullptr,
          "Hwfp_CheckLicense garbage -> 5 with detail json");
    Check(res && std::strstr(res, "\"valid\": false") != nullptr,
          "garbage license detail says valid:false");

    // 5. 释放（含 NULL）
    Hwfp_Free(json);
    Hwfp_Free(json2);
    Hwfp_Free(res);
    Hwfp_Free(nullptr);
    std::printf("  [ok] Hwfp_Free (payloads + NULL)\n");

    std::printf("[dlltest] %s\n", g_failed ? "FAIL" : "OK");
    return g_failed ? 1 : 0;
}
