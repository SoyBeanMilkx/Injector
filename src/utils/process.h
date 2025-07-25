#pragma once

#include <string>
#include <vector>
#include "types.h"

namespace utils {

    class ProcessUtils {
    public:
        ProcessUtils();
        ~ProcessUtils();

        // 进程控制
        bool AttachProcess(pid_t pid);
        bool DetachProcess(pid_t pid);

        // 寄存器操作
        bool GetRegisters(pid_t pid, user_regs_struct_arm64* regs);
        bool SetRegisters(pid_t pid, const user_regs_struct_arm64* regs);

        // 远程调用
        uint64_t CallRemoteFunction(pid_t pid, uint64_t func_addr,
                                    const std::vector<uint64_t>& args);

        // 模块信息
        uint64_t GetModuleBase(pid_t pid, const std::string& module_name);
        std::string GetProcessName(pid_t pid);
        std::string GetProcessArchitecture(pid_t pid);
        bool IsProcess64Bit(pid_t pid);

    private:
        bool SetupRemoteCall(RemoteCallContext* ctx, uint64_t func_addr,
                             const std::vector<uint64_t>& args);
        bool ExecuteRemoteCall(RemoteCallContext* ctx);
        bool WaitForSignal(pid_t pid, int expected_signal);
    };

} // namespace utils
