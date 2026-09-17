// 测试入口：所有测试 TU 通过 TEST 宏自注册，main 只负责统一执行
#include "tests/test_util.h"

int main() { return RunAllTests(); }
