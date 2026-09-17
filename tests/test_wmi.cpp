// ============================================================
// T5 wmi 通道单测：值变换纯函数（R12 日期 / MAC 统一 / 容量换算）
// ============================================================
#include "tests/test_util.h"
#include "channels/wmi_util.h"
#include "channels/wmi_channel.h"
#include "core/channel_registry.h"
#include "core/field.h"
#include <algorithm>

TEST(wmi_util, datetime_to_iso_date) {
    CHECK_STREQ(wmi_util::DatetimeToIsoDate("20240725000000.000000+000"), "2024-07-25");
    CHECK_STREQ(wmi_util::DatetimeToIsoDate("19991231000000.000000-060"), "1999-12-31");
    CHECK_STREQ(wmi_util::DatetimeToIsoDate(""), "");           // 空输入
    CHECK_STREQ(wmi_util::DatetimeToIsoDate("202407"), "");     // 位数不足
    CHECK_STREQ(wmi_util::DatetimeToIsoDate("2024072X000000+000"), "");  // 非数字
}

TEST(wmi_util, mac_normalize) {
    CHECK_STREQ(wmi_util::MacNormalize("AA:BB:CC:DD:EE:03"), "AABBCCDDEE03");
    CHECK_STREQ(wmi_util::MacNormalize("aa-bb-cc-dd-ee-02"), "AABBCCDDEE02");  // 小写+连字符
    CHECK_STREQ(wmi_util::MacNormalize(""), "");
}

TEST(wmi_util, capacity_bytes_to_mb) {
    CHECK_STREQ(wmi_util::CapacityBytesToMb("17179869184"), "16384");   // 16 GiB
    CHECK_STREQ(wmi_util::CapacityBytesToMb("0"), "0");
    CHECK_STREQ(wmi_util::CapacityBytesToMb(""), "");
    CHECK_STREQ(wmi_util::CapacityBytesToMb("12ab"), "");               // 非数字整体拒绝
}

TEST(wmi_channel, registered_and_table_covers_fields) {
    const auto& names = ChannelRegistry::Instance().Names();
    CHECK(std::find(names.begin(), names.end(), "wmi") != names.end());
    WmiChannel ch;
    CHECK(ch.DefaultPriority() == 20);
    const auto fields = ch.SupportedFields();
    CHECK(fields.size() >= 25);                       // 查询表规模下限
    for (auto k : fields) CHECK(FindFieldDef(k) != nullptr);
}

TEST(wmi_channel, spec_table_regression_counts) {
    // R6 防回归：WmiSpec 位置式初始化曾把 note 误绑为 pnp_filter，
    // 导致 disk.serial/memory.size/disk.size_bytes 全行被过滤（验收 P0）。
    CHECK_EQ(wmi_channel_test::NicFilterSpecCountForTest(), 2);   // 网卡 2 条
    CHECK_EQ(wmi_channel_test::GpuFilterSpecCountForTest(), 2);   // 显卡 2 条
    // T12：磁盘 4 条盘位键 + 网卡 2 条 MAC 键 = 6
    CHECK_EQ(wmi_channel_test::KeyedSpecCountForTest(), 6);
}

TEST(wmi_util, gpu_virtual_filter_r6) {
    using wmi_util::GpuPnpLikelyPhysical;
    using wmi_util::GpuNameLooksVirtual;
    // 真机证据：真显卡均 PCI\\VEN_*（NVIDIA/AMD/Intel），保物理
    CHECK(GpuPnpLikelyPhysical("PCI\\VEN_1234&DEV_5678&SUBSYS_9ABCDEF0&REV_01\\0&00000000&0&0001"));
    CHECK(GpuPnpLikelyPhysical("PCI\\VEN_1234&DEV_5678&SUBSYS_9ABCDEF1&REV_02\\0&00000000&0&0002"));
    CHECK(GpuPnpLikelyPhysical("pci\\ven_8086&dev_4680"));                  // 大小写不敏感
    // 真机证据：GameViewer 虚拟显示适配器 = ROOT\\DISPLAY；Microsoft 基本显示 = ROOT\\BasicDisplay
    CHECK(!GpuPnpLikelyPhysical("ROOT\\DISPLAY\\0000"));
    CHECK(!GpuPnpLikelyPhysical("ROOT\\BasicDisplay\\0000"));
    CHECK(!GpuPnpLikelyPhysical("SWD\\MSRRAS\\MS_NDISWAN"));
    CHECK(!GpuPnpLikelyPhysical(""));
    // 名称黑名单兜底（个别虚拟显示驱动可能挂 PCI 总线）
    CHECK(GpuNameLooksVirtual("GameViewer Virtual Display Adapter"));
    CHECK(GpuNameLooksVirtual("USBMMIDD Display Adapter"));
    CHECK(GpuNameLooksVirtual("Microsoft Remote Display Adapter"));
    CHECK(GpuNameLooksVirtual("Parsec Virtual Display"));
    CHECK(!GpuNameLooksVirtual("NVIDIA GeForce RTX 5090"));
    CHECK(!GpuNameLooksVirtual("AMD Radeon(TM) Graphics"));
    CHECK(!GpuNameLooksVirtual("Intel(R) UHD Graphics 770"));
}

TEST(wmi_util, nic_pnp_filter_r6) {
    // R6：PNP 设备实例 ID 总线前缀判物理——PCI/USB 物理，ROOT/SWD/ACPI/空 排除
    using wmi_util::NicPnpLikelyPhysical;
    CHECK(NicPnpLikelyPhysical("PCI\\VEN_1234&DEV_5678&SUBSYS_9ABCDEF2&REV_03\\000000"));
    CHECK(NicPnpLikelyPhysical("pci\\ven_4321&dev_8765\\0&1234567"));            // 大小写不敏感
    CHECK(NicPnpLikelyPhysical("USB\\VID_0B95&PID_7720\\ABC123"));               // USB 网卡属物理
    CHECK(!NicPnpLikelyPhysical("ROOT\\VMWARE\\0000"));                          // VMware VMnet
    CHECK(!NicPnpLikelyPhysical("ROOT\\MS_NDISWANMN\\0000"));
    CHECK(!NicPnpLikelyPhysical("SWD\\MSRRAS\\MS_NDISWAN"));
    CHECK(!NicPnpLikelyPhysical("ACPI\\FOO\\1"));
    CHECK(!NicPnpLikelyPhysical(""));
}
