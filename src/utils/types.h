#pragma once

#include <cstdint>
#include <sys/types.h>

namespace utils {

// ARM64寄存器结构
    struct user_regs_struct_arm64 {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    };

// 远程调用上下文
    struct RemoteCallContext {
        pid_t pid;
        user_regs_struct_arm64 orig_regs;
        user_regs_struct_arm64 regs;
        bool regs_saved;
    };

} // namespace utils
