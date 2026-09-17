#include <windows.h>
// ============================================================
// 冒烟入口：走 CollectorManager（线程池并发调度 + 归并器），
// 输出归并后的字段结果、整机/子指纹与耗时——T8 CLI 的预演
// 用法: build.cmd smoke && build\hwfp_smoke.exe
// ============================================================
#include "core/collector_manager.h"
#include "core/field.h"
#include "fingerprint/fingerprint_engine.h"
#include <cstdio>

int main() {
    SetConsoleOutputCP(CP_UTF8);

    CollectorManager mgr;
    CollectorManager::RunResult rr = mgr.Run();

    std::printf("merged fields: %d instances, %.0f ms\n", rr.instances, rr.ms);
    for (const auto& u : rr.unavailable)
        std::printf("unavailable channel: %s\n", u.c_str());

    const auto fingerprint = fp::ComputeFingerprint(rr.merged);
    std::printf("master fingerprint: %s\n", fingerprint.master.c_str());
    for (const auto& g : fingerprint.sub)
        std::printf("  sub[%-6s] = %s\n", g.first.c_str(), g.second.c_str());
    std::printf("\n");

    for (const auto& kv : rr.merged) {
        const FieldDef* def = FindFieldDef(kv.first);
        for (const auto& r : kv.second) {
            char conf[16] = "";
            if (!r.confidence.empty())
                std::snprintf(conf, sizeof conf, " (%s)", r.confidence.c_str());
            std::printf("[%-8s] %-22s[%d] = %s%s%s\n",
                        r.channel.empty() ? "-" : r.channel.c_str(),
                        def ? def->name : "?", r.index,
                        r.value.empty() ? "<empty>" : r.value.c_str(),
                        conf, r.placeholder ? " <placeholder>" : "");
        }
    }
    return 0;
}
