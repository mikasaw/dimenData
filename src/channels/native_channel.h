// ============================================================
// Native 通道：CPUID / IP Helper / CNG / 存储端口 IOCTL / TBS
// 注意：winsock2.h 必须先于 windows.h（iptypes.h 的 GAA 段依赖
// _WINSOCK2API_，见开发计划 §10 工具链备注）
// ============================================================
#pragma once
#include <mutex>
#include <string>
#include <vector>
#include "core/ichannel.h"
#include "channels/native_util.h"

struct NativeDisk {
    int         number = 0;  // 物理盘位号（\.\PhysicalDriveN 的 N），
                             // 作为 instance_key 供逐盘跨通道对齐
    std::string model;       // vendor + product（与 WMI disk.model 口径一致）
    std::string serial;      // 原始串（R4 归一化在归并层）
    std::string firmware;
};

struct NativeCpu {
    std::string brand;
    std::string id_hex;     // leaf1 EDX:EAX，WMI 同格式
};

class NativeChannel : public IChannel {
public:
    const char* Name() const override { return "native"; }
    int DefaultPriority() const override { return 15; }

    bool Available() override { return true; }   // CPUID 恒存在
    std::vector<FieldKey> SupportedFields() const override;
    std::vector<FieldResult> Collect(FieldKey key) override;

private:
    void EnsureProbed();

    bool probed_ = false;
    NativeCpu cpu_;
    std::vector<NativeDisk> disks_;
    std::vector<native_util::NvidiaGpu> nvidia_gpus_;  // nvidia-smi 采集（可能为空）
    std::string nvidia_note_;                          // 空 = 采到；否则为降级原因
    bool nics_done_ = false;      // 网卡逐键枚举，无需缓存
    int  tbs_code_ = -1;          // 0=TPM 可用；其他为 TBS 错误码；-1 未测
    std::string crypto_result_;   // "pass" 或失败说明
    std::mutex  mu_;              // 保护懒探针
};
