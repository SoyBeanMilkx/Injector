#pragma once

#include <cstdint>
#include <cstddef>
#include <sys/types.h>

namespace utils {

    class MemoryUtils {
    public:
        MemoryUtils();
        ~MemoryUtils();

        // 内存读写
        bool ReadProcessMemory(pid_t pid, uint64_t addr, void* buf, size_t size);
        bool WriteProcessMemory(pid_t pid, uint64_t addr, const void* buf, size_t size);

        // 内存权限
        bool SetMemoryPermission(pid_t pid, uint64_t addr, size_t size, int prot);

        // 内存搜索
        uint64_t FindExecutableSpace(pid_t pid, size_t size);

    private:
        bool ReadWord(pid_t pid, uint64_t addr, long* value);
        bool WriteWord(pid_t pid, uint64_t addr, long value);
    };

} // namespace utils
