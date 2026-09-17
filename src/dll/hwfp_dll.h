// ============================================================
// hwfp.dll —— C ABI 集成接口（供宿主应用加载的设备指纹/授权校验库）
//
// 约定：
//  - 全部字符串 UTF-8；输出缓冲用 Hwfp_Free 释放（同 CRT 堆）
//  - 返回码沿用 CLI 退出码语义：
//      0 成功/授权有效
//      2 参数错误（空指针、阈值越界）
//      3 采集失败（无任何字段产出）
//      5 授权格式或签名无效
//      6 授权已过期或机器不匹配
//  - 线程模型：各入口相互独立、可重入（内部自带线程池与锁）；
//    集成建议在授权校验场景按需调用（如启动时一次），高频并发
//    调用 Hwfp_Collect 未做专项优化
//  - DLL 不隐式读取配置文件：默认配置 = 全部通道默认优先级/权重；
//    需要定制时用 Hwfp_CollectWithConfig 传入配置 JSON 文本
//  - 静态链接 CRT（/MT）：宿主与 DLL 各自持 CRT 状态，
//    输出缓冲必须用 Hwfp_Free 释放，不可跨模块 free
// ============================================================
#pragma once

#ifdef __cplusplus
#define HWFP_EXTERN extern "C"
#else
#define HWFP_EXTERN
#endif

#ifdef HWFP_BUILD_DLL
#define HWFP_API HWFP_EXTERN __declspec(dllexport)
#else
#define HWFP_API HWFP_EXTERN
#endif

// 工具版本（与 CLI --version 同源）
HWFP_API const char* Hwfp_Version(void);

// 采集本机并生成设备指纹，输出 schema v1 JSON（同 CLI 默认输出）。
// 成功返回 0 并置 *out_json（调用方 Hwfp_Free）；失败返回 3，*out_json 置空
HWFP_API int Hwfp_Collect(char** out_json);

// 同 Hwfp_Collect，但用调用方提供的配置 JSON 文本（结构同 config/hwfp.json）。
// 配置解析失败返回 2，*out_json 置空
HWFP_API int Hwfp_CollectWithConfig(const char* config_json_utf8, char** out_json);

// 授权校验：签名 + 有效期 + 机器绑定（绑定需本机采集，按默认配置）。
// threshold <=0 或 >1 时用默认 0.85。
// 返回 0/5/6（语义见上），*out_json 为校验明细 JSON（即使校验失败也非空，
// 除非 license_json/pubkey 非法导致返回 2）。
HWFP_API int Hwfp_CheckLicense(const char* license_json_utf8,
                               const char* pubkey_b64,
                               double threshold,
                               char** out_result_json);

// 释放本库输出的缓冲
HWFP_API void Hwfp_Free(char* p);
