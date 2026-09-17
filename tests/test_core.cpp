// ============================================================
// T1 核心骨架单测：字段定义表 / 名称查找 / 通道注册中心
// ============================================================
#include "tests/test_util.h"
#include "core/field.h"
#include "core/channel_registry.h"
#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace {

// —— mock 通道：优先级不同，验证注册与按优先级创建 ——
class MockAlphaChannel : public IChannel {
public:
    const char* Name() const override { return "alpha"; }
    int DefaultPriority() const override { return 10; }
    bool Available() override { return true; }
    std::vector<FieldKey> SupportedFields() const override { return { FieldKey::kBoardSerial }; }
    std::vector<FieldResult> Collect(FieldKey) override { return {}; }
};

class MockBetaChannel : public IChannel {
public:
    const char* Name() const override { return "beta"; }
    int DefaultPriority() const override { return 5; }
    bool Available() override { return false; }  // 不影响注册，只在调度时被剔除
    std::vector<FieldKey> SupportedFields() const override { return { FieldKey::kSysSerial }; }
    std::vector<FieldResult> Collect(FieldKey) override { return {}; }
};

REGISTER_CHANNEL(MockAlphaChannel)
REGISTER_CHANNEL(MockBetaChannel)

} // namespace

TEST(core, field_def_table) {
    const int n = GetFieldDefCount();
    CHECK(n > 40);  // 字段清单规模下限，防止表被意外清空

    const FieldDef* bs = FindFieldDef(FieldKey::kBoardSerial);
    CHECK(bs != nullptr);
    if (bs) {
        CHECK_STREQ(bs->name, "board.serial");
        CHECK(bs->strategy == MergeStrategy::Consensus);
        CHECK(bs->weight == 20);
        CHECK(bs->group == FpGroup::Board);
    }
    const FieldDef* ss = FindFieldDef(FieldKey::kSysSerial);
    CHECK(ss != nullptr && ss->weight == 30);

    // 权重为 0 的只采集字段存在（显示器/SecureBoot/TPM）
    CHECK(FindFieldDef(FieldKey::kMonitorSerial)->weight == 0);
    CHECK(FindFieldDef(FieldKey::kOsSecureBoot)->weight == 0);
}

TEST(core, field_name_lookup) {
    CHECK(FieldKeyFromName("sys.serial") == FieldKey::kSysSerial);
    CHECK(FieldKeyFromName("board.serial") == FieldKey::kBoardSerial);
    CHECK(FieldKeyFromName("no.such.field") == FieldKey::kFieldCount);   // 越界哨兵
    CHECK(FieldKeyFromName(nullptr) == FieldKey::kFieldCount);
    CHECK(FindFieldDef(FieldKey::kFieldCount) == nullptr);               // 哨兵无定义
    CHECK(FindFieldDef(static_cast<FieldKey>(-1)) == nullptr);
}

TEST(core, field_names_unique) {
    std::set<std::string> names;
    for (int i = 0; i < GetFieldDefCount(); ++i)
        names.insert(GetFieldDefs()[i].name);
    CHECK_EQ((int)names.size(), GetFieldDefCount());
}

TEST(core, registry_register_and_order) {
    auto& reg = ChannelRegistry::Instance();
    CHECK(reg.Count() >= 2);  // 至少包含本文件的 alpha/beta

    const auto names = reg.Names();
    CHECK(std::find(names.begin(), names.end(), "alpha") != names.end());
    CHECK(std::find(names.begin(), names.end(), "beta") != names.end());

    // 创建实例按优先级升序：beta(5) 在 alpha(10) 之前
    auto insts = reg.CreateAll();
    CHECK(insts.size() == names.size());
    for (size_t i = 1; i < insts.size(); ++i)
        CHECK(insts[i - 1]->DefaultPriority() <= insts[i]->DefaultPriority());

    // 同名重复注册以覆盖为准（注册键为宏传入的类名字符串），不产生重复条目；
    // 按实例名计数而非精确总数，后续任务链入真实通道不会误报
    const int betaBefore = (int)std::count(names.begin(), names.end(), "beta");
    reg.Register("MockBetaChannel", []() -> std::unique_ptr<IChannel> {
        return std::unique_ptr<IChannel>(new MockBetaChannel());
    });
    const auto namesAfter = reg.Names();
    CHECK_EQ((int)std::count(namesAfter.begin(), namesAfter.end(), "beta"), betaBefore);
}

// main 在 tests/test_main.cpp，各测试 TU 通过 TEST 宏自注册
