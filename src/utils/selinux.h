#pragma once

#include <string>
#include <sys/types.h>

namespace utils {

    class SELinuxUtils {
    public:
        // 检查SELinux状态
        static bool IsEnforcing();
        static bool IsPermissive();
        static bool IsDisabled();

        // 设置SELinux模式
        static bool SetEnforcing();
        static bool SetPermissive();

        // 获取/设置进程上下文
        static std::string GetProcessContext(pid_t pid);
        static bool SetProcessContext(pid_t pid, const std::string& context);

    private:
        static int GetEnforceStatus();
        static bool SetEnforceStatus(int status);
    };

} // namespace utils