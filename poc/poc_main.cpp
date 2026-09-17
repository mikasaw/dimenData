// ============================================================
// M1 POC —— 入口：依次执行四个通道并输出汇总
// 输出为 UTF-8 文本，可重定向到文件供《采集项可用性矩阵》整理
// ============================================================
#include "poc_common.h"
#include <chrono>
#include <cstdio>
#include <map>

int main() {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== dimenData M1 POC：多通道采集验证 ===\n\n");

    const auto t0 = std::chrono::steady_clock::now();
    PocSmbios();
    PocWmi();
    PocRegistry();
    PocNative();
    const double ms = std::chrono::duration<double, std::milli>(
                          std::chrono::steady_clock::now() - t0).count();

    printf("=== 逐项结果（<empty> 表示未取到）===\n");
    for (const auto& f : PocResults()) {
        std::string suffix;
        if (!f.note.empty()) suffix = "   ; " + f.note;
        printf("[%-8s] %-30s = %s%s\n", f.channel.c_str(), f.field.c_str(),
               f.value.empty() ? "<empty>" : f.value.c_str(), suffix.c_str());
    }

    // 通道汇总：统计各通道取到/未取到的字段数
    std::map<std::string, std::pair<int, int>> stat;
    for (const auto& f : PocResults()) {
        if (f.field == "channel.available" || f.field == "query.error") continue;
        auto& s = stat[f.channel];
        ++(f.value.empty() ? s.second : s.first);
    }
    printf("\n=== 通道汇总 ===\n");
    for (const auto& kv : stat)
        printf("%-8s: 取到 %2d 项, 未取到 %2d 项\n",
               kv.first.c_str(), kv.second.first, kv.second.second);
    printf("字段总数 %zu, 总耗时 %.0f ms\n", PocResults().size(), ms);
    return 0;
}
