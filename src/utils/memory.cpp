#include "memory.h"
#include "logger.h"
#include <sys/ptrace.h>
#include <cstring>
#include <errno.h>
#include <fstream>
#include <sstream>

namespace utils {

    MemoryUtils::MemoryUtils() {
    }

    MemoryUtils::~MemoryUtils() {
    }

    bool MemoryUtils::ReadProcessMemory(pid_t pid, uint64_t addr, void* buf, size_t size) {
        LOGD("ReadProcessMemory: pid=%d, addr=0x%lx, size=%zu", pid, addr, size);

        uint8_t* dst = (uint8_t*)buf;
        size_t remaining = size;

        while (remaining > 0) {
            size_t to_read = (remaining > sizeof(long)) ? sizeof(long) : remaining;

            long data;
            if (!ReadWord(pid, addr, &data)) {
                LOGE("  Failed to read at 0x%lx", addr);
                return false;
            }

            memcpy(dst, &data, to_read);

            dst += to_read;
            addr += to_read;
            remaining -= to_read;
        }

        LOGD("  Successfully read %zu bytes", size);
        return true;
    }

    bool MemoryUtils::WriteProcessMemory(pid_t pid, uint64_t addr, const void* buf, size_t size) {
        LOGD("WriteProcessMemory: pid=%d, addr=0x%lx, size=%zu", pid, addr, size);

        const uint8_t* src = (const uint8_t*)buf;
        size_t remaining = size;

        while (remaining > 0) {
            size_t to_write = (remaining > sizeof(long)) ? sizeof(long) : remaining;

            long data = 0;
            if (to_write < sizeof(long)) {
                if (!ReadWord(pid, addr, &data)) {
                    LOGE("  Failed to read original data at 0x%lx", addr);
                    return false;
                }
            }

            memcpy(&data, src, to_write);

            if (!WriteWord(pid, addr, data)) {
                LOGE("  Failed to write at 0x%lx", addr);
                return false;
            }

            src += to_write;
            addr += to_write;
            remaining -= to_write;
        }

        LOGD("  Successfully wrote %zu bytes", size);
        return true;
    }

    bool MemoryUtils::ReadWord(pid_t pid, uint64_t addr, long* value) {
        errno = 0;
        *value = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
        if (errno != 0) {
            LOGE("PTRACE_PEEKDATA failed at 0x%lx: %s", addr, strerror(errno));
            return false;
        }
        return true;
    }

    bool MemoryUtils::WriteWord(pid_t pid, uint64_t addr, long value) {
        if (ptrace(PTRACE_POKEDATA, pid, addr, value) == -1) {
            LOGE("PTRACE_POKEDATA failed at 0x%lx: %s", addr, strerror(errno));
            return false;
        }
        return true;
    }

    bool MemoryUtils::SetMemoryPermission(pid_t pid, uint64_t addr, size_t size, int prot) {
        LOGW("SetMemoryPermission not fully implemented");
        return true;
    }

    uint64_t MemoryUtils::FindExecutableSpace(pid_t pid, size_t size) {
        char maps_path[256];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

        std::ifstream maps(maps_path);
        if (!maps.is_open()) {
            LOGE("Failed to open %s", maps_path);
            return 0;
        }

        std::string line;
        while (std::getline(maps, line)) {
            uint64_t start, end;
            char perms[5];

            if (sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) == 3) {
                if (perms[2] == 'x' && (end - start) >= size) {
                    maps.close();
                    LOGD("Found executable space at 0x%lx, size: 0x%lx", start, end - start);
                    return start;
                }
            }
        }

        maps.close();
        return 0;
    }

}