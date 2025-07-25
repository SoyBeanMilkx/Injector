#include "process.h"
#include "logger.h"
#include "memory.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <cstring>

namespace utils {

    ProcessUtils::ProcessUtils() {
    }

    ProcessUtils::~ProcessUtils() {
    }

    bool ProcessUtils::AttachProcess(pid_t pid) {
        LOGD("Attempting to attach to process %d", pid);

        char proc_path[256];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
        if (access(proc_path, F_OK) != 0) {
            LOGE("Process %d does not exist", pid);
            return false;
        }

        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
            LOGE("ptrace attach failed: %s (errno=%d)", strerror(errno), errno);
            if (errno == EPERM) {
                LOGE("Permission denied. Make sure you have root privileges");
            } else if (errno == ESRCH) {
                LOGE("No such process");
            }
            return false;
        }

        LOGD("ptrace attach succeeded, waiting for process to stop...");

        int status;
        if (waitpid(pid, &status, 0) == -1) {
            LOGE("waitpid failed: %s (errno=%d)", strerror(errno), errno);
            return false;
        }

        if (!WIFSTOPPED(status)) {
            LOGE("Process not stopped after attach (status=0x%x)", status);
            return false;
        }

        LOGI("Successfully attached to process %d (stop signal=%d)", pid, WSTOPSIG(status));
        return true;
    }

    bool ProcessUtils::DetachProcess(pid_t pid) {
        if (ptrace(PTRACE_DETACH, pid, nullptr, nullptr) == -1) {
            LOGE("ptrace detach failed: %s", strerror(errno));
            return false;
        }

        LOGI("Successfully detached from process %d", pid);
        return true;
    }

    bool ProcessUtils::GetRegisters(pid_t pid, user_regs_struct_arm64* regs) {
        struct iovec iov;
        iov.iov_base = regs;
        iov.iov_len = sizeof(*regs);

        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
            LOGE("PTRACE_GETREGSET failed: %s", strerror(errno));
            return false;
        }

        return true;
    }

    bool ProcessUtils::SetRegisters(pid_t pid, const user_regs_struct_arm64* regs) {
        struct iovec iov;
        iov.iov_base = (void*)regs;
        iov.iov_len = sizeof(*regs);

        if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
            LOGE("PTRACE_SETREGSET failed: %s", strerror(errno));
            return false;
        }

        return true;
    }

    uint64_t ProcessUtils::CallRemoteFunction(pid_t pid, uint64_t func_addr,
                                              const std::vector<uint64_t>& args) {
        LOGD("CallRemoteFunction: pid=%d, func=0x%lx, args_count=%zu",
             pid, func_addr, args.size());

        RemoteCallContext ctx;
        ctx.pid = pid;
        ctx.regs_saved = false;

        // 保存原始寄存器
        LOGD("  Getting original registers...");
        if (!GetRegisters(pid, &ctx.orig_regs)) {
            LOGE("  Failed to get original registers");
            return 0;
        }
        ctx.regs_saved = true;
        LOGD("  Original registers saved (PC=0x%lx, SP=0x%lx)",
             ctx.orig_regs.pc, ctx.orig_regs.sp);

        // 设置远程调用
        LOGD("  Setting up remote call...");
        if (!SetupRemoteCall(&ctx, func_addr, args)) {
            LOGE("  Failed to setup remote call");
            SetRegisters(pid, &ctx.orig_regs);
            return 0;
        }

        // 执行远程调用
        LOGD("  Executing remote call...");
        if (!ExecuteRemoteCall(&ctx)) {
            LOGE("  Failed to execute remote call");
            SetRegisters(pid, &ctx.orig_regs);
            return 0;
        }

        // 获取返回值
        LOGD("  Getting result registers...");
        user_regs_struct_arm64 result_regs;
        if (!GetRegisters(pid, &result_regs)) {
            LOGE("  Failed to get result registers");
            SetRegisters(pid, &ctx.orig_regs);
            return 0;
        }

        uint64_t result = result_regs.regs[0];
        LOGD("  Function returned: 0x%lx", result);

        // 恢复原始寄存器
        LOGD("  Restoring original registers...");
        if (!SetRegisters(pid, &ctx.orig_regs)) {
            LOGE("  Failed to restore original registers");
        }

        LOGD("CallRemoteFunction completed, result=0x%lx", result);
        return result;
    }

    bool ProcessUtils::SetupRemoteCall(RemoteCallContext* ctx, uint64_t func_addr,
                                       const std::vector<uint64_t>& args) {
        // 复制原始寄存器
        ctx->regs = ctx->orig_regs;

        // 设置栈指针 - 确保16字节对齐
        ctx->regs.sp = (ctx->orig_regs.sp - 0x100) & ~0xF;

        // 设置参数（ARM64前8个参数通过x0-x7传递）
        for (size_t i = 0; i < args.size() && i < 8; i++) {
            ctx->regs.regs[i] = args[i];
        }

        // 如果参数超过8个，需要压栈
        if (args.size() > 8) {
            MemoryUtils memory_utils;
            uint64_t stack_addr = ctx->regs.sp;
            for (size_t i = 8; i < args.size(); i++) {
                if (!memory_utils.WriteProcessMemory(ctx->pid, stack_addr, &args[i], sizeof(uint64_t))) {
                    LOGE("Failed to write stack argument %zu", i);
                    return false;
                }
                stack_addr += sizeof(uint64_t);
            }
        }

        // 设置PC指向目标函数
        ctx->regs.pc = func_addr;

        // 设置返回地址为0，这样函数返回时会触发SIGSEGV
        ctx->regs.regs[30] = 0;  // x30是链接寄存器(LR)

        LOGD("Setting up remote call: PC=0x%lx, SP=0x%lx", ctx->regs.pc, ctx->regs.sp);

        return SetRegisters(ctx->pid, &ctx->regs);
    }

    bool ProcessUtils::ExecuteRemoteCall(RemoteCallContext* ctx) {
        if (ptrace(PTRACE_CONT, ctx->pid, nullptr, nullptr) == -1) {
            LOGE("PTRACE_CONT failed: %s", strerror(errno));
            return false;
        }

        return WaitForSignal(ctx->pid, SIGSEGV);
    }

    bool ProcessUtils::WaitForSignal(pid_t pid, int expected_signal) {
        int status;

        while (true) {
            if (waitpid(pid, &status, 0) == -1) {
                LOGE("waitpid failed: %s", strerror(errno));
                return false;
            }

            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                if (sig == expected_signal) {
                    LOGD("Received expected signal: %d", sig);
                    return true;
                } else if (sig == SIGSTOP || sig == SIGCONT) {
                    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
                        LOGE("PTRACE_CONT failed: %s", strerror(errno));
                        return false;
                    }
                    continue;
                } else {
                    LOGE("Received unexpected signal: %d", sig);
                    return false;
                }
            } else if (WIFEXITED(status)) {
                LOGE("Process exited with status: %d", WEXITSTATUS(status));
                return false;
            }
        }
    }

    uint64_t ProcessUtils::GetModuleBase(pid_t pid, const std::string& module_name) {
        char maps_path[256];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

        LOGD("GetModuleBase: pid=%d, module=%s", pid, module_name.c_str());

        std::ifstream maps(maps_path);
        if (!maps.is_open()) {
            LOGE("Failed to open %s: %s", maps_path, strerror(errno));
            return 0;
        }

        std::string line;
        bool found = false;
        while (std::getline(maps, line)) {
            if (line.find(module_name) != std::string::npos &&
                line.find(" r-xp ") != std::string::npos) {  // 只查找可执行段
                // 解析基址
                uint64_t base;
                if (sscanf(line.c_str(), "%lx", &base) == 1) {
                    maps.close();
                    LOGD("  Found module %s at base 0x%lx", module_name.c_str(), base);
                    LOGD("  Map line: %s", line.c_str());
                    return base;
                }
            }
        }

        maps.close();
        LOGD("  Module %s not found in process %d", module_name.c_str(), pid);
        return 0;
    }

    std::string ProcessUtils::GetProcessName(pid_t pid) {
        char path[256];
        char name[256];

        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            return "";
        }

        ssize_t len = read(fd, name, sizeof(name) - 1);
        close(fd);

        if (len > 0) {
            name[len] = '\0';
            return std::string(name);
        }

        return "";
    }

    bool ProcessUtils::IsProcess64Bit(pid_t pid) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            return false;
        }

        Elf64_Ehdr ehdr;
        ssize_t n = read(fd, &ehdr, sizeof(ehdr));
        close(fd);

        if (n != sizeof(ehdr)) {
            return false;
        }

        if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
            return false;
        }

        return ehdr.e_ident[EI_CLASS] == ELFCLASS64;
    }

    std::string ProcessUtils::GetProcessArchitecture(pid_t pid) {
        if (!IsProcess64Bit(pid)) {
            return "arm";
        }
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            return "unknown";
        }

        Elf64_Ehdr ehdr;
        ssize_t n = read(fd, &ehdr, sizeof(ehdr));
        close(fd);

        if (n != sizeof(ehdr)) {
            return "unknown";
        }

        if (ehdr.e_machine == EM_AARCH64) {
            return "arm64";
        } else if (ehdr.e_machine == EM_ARM) {
            return "arm";
        }

        return "unknown";
    }

}