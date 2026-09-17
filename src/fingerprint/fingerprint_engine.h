// ============================================================
// 指纹引擎（开发计划 §3.3）：规范化 → 加权选取 → SHA-256 → 整机 + 子指纹
//
// 哈希输入契约：
//   整机 = SHA256("HWFP-V1\n" + 各参与行)
//   子指纹 = SHA256("HWFP-V1-<group>\n" + 该组各参与行)
//   参与行 = "字段键=规范化值\n"，按 (字段键, 实例值) 字典序排序保证确定性
// 权重：fields.def 默认 + 可选覆盖；weight=0 只采集不入指纹；
//       缺失/空值字段整行跳过（缺失 ≠ 空串）
//
// 算法版本（kAlgoVersion）：指纹结果由「字段集 + 权重 + 规范化规则」共同决定，
// 任一变更都会改变指纹（对相关机器）。报告写入该版本号，--verify 据此区分
// "报告被篡改"与"算法已演进"——版本不一致时完整性不可判定（退出码 4），
// 而 match/similarity 仍有效（两侧均按当前算法重算）。
// 版本历史：1 = 初版（T7，至 R4/R5/R6 收尾）；2 = gpu.uuid 参与指纹（gpu 组，权重 5）
// 过渡期说明：v1 报告体（无 gpu.uuid）在算法 v2 下重算时不含 gpu 组，
// 而当前指纹含该组 → 同机相似度约 160/165 ≈ 0.97（非 1.0），属预期损耗
// ============================================================
#pragma once
#include <map>
#include <string>
#include <vector>
#include "core/field.h"
#include "core/field_result.h"
#include "core/merger.h"

namespace fp {

constexpr int kAlgoVersion = 2;   // 变更字段集/权重/规范化规则时必须递增

struct FingerprintOutput {
    int         algo = kAlgoVersion;                 // 算法版本（解析旧报告时为报告内记录值）
    std::string master;                              // 整机指纹（64 hex）
    std::map<std::string, std::string> sub;          // 组名 → 子指纹（64 hex）
    std::vector<std::string> contributors;           // 参与行（审计/诊断，与哈希输入同序）
};

// value_override：字段权重覆盖（配置加载属 T8，可空）
FingerprintOutput ComputeFingerprint(
    const MergedResults& merged,
    const std::map<FieldKey, int>* weight_override = nullptr);

// 单字段值的入指纹规范化（R1/R2/R4/R12 的指纹侧）：
//   cpu.id → R1 统一 + R2 屏蔽 APIC；disk.serial → 去 [ _.- ] + 大写（R4）；
//   nic.mac → 去分隔符大写；bios.release_date → ISO；其余 trim
std::string NormalizeValueForFingerprint(FieldKey key, const std::string& channel,
                                         const std::string& raw);

// 相似度评分（F6 校验模式）：子指纹按组权重加权重合率 ∈ [0,1]。
// 只统计两侧出现组的并集；组权重随 weight_override 联动（T7 验收备忘）
double Similarity(const FingerprintOutput& a, const FingerprintOutput& b,
                  const std::map<FieldKey, int>* weight_override = nullptr);

} // namespace fp
