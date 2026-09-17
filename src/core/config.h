// ============================================================
// 配置文件（config/hwfp.json）加载
// 结构见 config/hwfp.json；通配键 "xxx.*" 展开为该前缀全部字段
// ============================================================
#pragma once
#include <map>
#include <string>
#include "core/field.h"

struct ChannelConf {
    bool enabled = true;
    int  priority = -1;    // -1 = 沿用通道默认
    std::map<std::string, int> options;   // 通道选项（如 wmi 的 tpm_probe=0/1）
};

struct HwfpConfig {
    // 通道覆盖（按通道名）
    std::map<std::string, ChannelConf> channels;
    // 字段覆盖：归并策略 / 指纹权重（已展开通配，按 FieldKey）
    std::map<FieldKey, MergeStrategy> field_strategy;
    std::map<FieldKey, int>           field_weight;
    // 执行参数
    size_t workers = 0;              // 0 = 自动（4）
    int    per_task_timeout_ms = 3000;   // 记录在案；硬超时依赖可中断查询，暂未强制
    // 输出
    std::string output_path;         // 空 = stdout
    bool        text_mode = false;   // true = 人类可读摘要

    // 从 JSON 文本加载；失败返回 false 并写 err
    bool LoadFromText(const std::string& json_text, std::string& err);
    bool LoadFromFile(const std::string& path, std::string& err);
};
