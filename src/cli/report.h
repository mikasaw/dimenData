// ============================================================
// 报告构建与解析（schema v1）
// collect 输出 / --verify 回读 共用同一 schema
// ============================================================
#pragma once
#include <string>
#include "core/collector_manager.h"
#include "fingerprint/fingerprint_engine.h"

namespace report {

// 构建 schema v1 JSON（UTF-8，紧凑格式）
std::string BuildJson(const CollectorManager::RunResult& rr,
                      const fp::FingerprintOutput& fp,
                      const std::string& tool_version);

// 从报告 JSON 还原合并结果与指纹（--verify 用）；
// 仅还原 ok=true 的字段实例，指纹直接取报告中记录的值
bool ParseReport(const std::string& json_text,
                 MergedResults& merged, fp::FingerprintOutput& fp,
                 std::string& err);

} // namespace report
