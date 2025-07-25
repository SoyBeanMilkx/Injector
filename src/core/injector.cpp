#include "injector.h"
#include "../utils/logger.h"
#include "../utils/memory.h"
#include "../utils/selinux.h"
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

namespace injector {

    using namespace utils;

    Injector::Injector() : selinux_enforcing_(false) {
        selinux_enforcing_ = SELinuxUtils::IsEnforcing();
        if (selinux_enforcing_) {
            LOGI("SELinux is in enforcing mode");
        }
    }

    Injector::~Injector() {
        module_cache_.clear();
    }

    bool Injector::Inject(pid_t target_pid, const std::string& library_path) {
        LOGI("Starting injection into process %d with library: %s", target_pid, library_path.c_str());

        // 1. 附加到目标进程
        if (!process_utils_.AttachProcess(target_pid)) {
            LOGE("Failed to attach to process %d", target_pid);
            return false;
        }

        // 2. 临时设置SELinux为宽容模式
        bool selinux_switched = false;
        if (selinux_enforcing_) {
            LOGI("Temporarily setting SELinux to permissive mode");
            if (SELinuxUtils::SetPermissive()) {
                selinux_switched = true;
            } else {
                LOGW("Failed to set SELinux to permissive, continuing anyway");
            }
        }

        bool injection_success = false;

        try {
            // 3. 获取dlopen地址
            uint64_t remote_dlopen = GetRemoteAddress(target_pid, "linker64", "__loader_dlopen");
            if (remote_dlopen == 0) {
                // Android 10+ 使用 __loader_dlopen
                remote_dlopen = GetRemoteAddress(target_pid, "libdl.so", "dlopen");
            }
            if (remote_dlopen == 0) {
                remote_dlopen = GetRemoteAddress(target_pid, "libc.so", "dlopen");
            }

            if (remote_dlopen == 0) {
                LOGE("Failed to find dlopen in target process");
                throw std::runtime_error("dlopen not found");
            }

            LOGI("Remote dlopen address: 0x%lx", remote_dlopen);

            // 4. 分配远程内存存储库路径
            uint64_t remote_mmap = GetRemoteAddress(target_pid, "libc.so", "mmap");
            if (remote_mmap == 0) {
                LOGE("Failed to find mmap in target process");
                throw std::runtime_error("mmap not found");
            }

            const auto MMAP_INVALID_FD = static_cast<uint64_t>(-1);

            uint64_t remote_path = CallRemoteFunction(target_pid, remote_mmap,
                                                      {0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, MMAP_INVALID_FD, 0});

            if (remote_path == 0) {
                LOGE("Failed to allocate memory in target process");
                throw std::runtime_error("mmap failed");
            }

            LOGI("Allocated remote memory at: 0x%lx", remote_path);

            // 5. 写入库路径
            MemoryUtils memory_utils;
            if (!memory_utils.WriteProcessMemory(target_pid, remote_path,
                                                 library_path.c_str(), library_path.length() + 1)) {
                LOGE("Failed to write library path to target process");
                throw std::runtime_error("write memory failed");
            }

            // 6. 调用dlopen加载库
            LOGI("Calling dlopen with path at 0x%lx", remote_path);
            uint64_t handle = CallRemoteFunction(target_pid, remote_dlopen,
                                                 {remote_path, RTLD_NOW});

            if (handle == 0) {
                LOGE("dlopen failed in target process");
                // 获取错误信息
                uint64_t dlerror_addr = GetRemoteAddress(target_pid, "libc.so", "dlerror");
                if (dlerror_addr != 0) {
                    uint64_t error_str = CallRemoteFunction(target_pid, dlerror_addr, {});
                    if (error_str != 0) {
                        char error_buf[256] = {0};
                        memory_utils.ReadProcessMemory(target_pid, error_str, error_buf, sizeof(error_buf) - 1);
                        LOGE("dlopen error: %s", error_buf);
                    }
                }
            } else {
                LOGI("Successfully loaded library, handle: 0x%lx", handle);
                injection_success = true;
            }

            // 7. 清理分配的内存
            uint64_t remote_munmap = GetRemoteAddress(target_pid, "libc.so", "munmap");
            if (remote_munmap != 0) {
                CallRemoteFunction(target_pid, remote_munmap, {remote_path, 4096});
            }

        } catch (const std::exception& e) {
            LOGE("Injection failed: %s", e.what());
        }

        // 8. 恢复SELinux模式
        if (selinux_switched) {
            LOGI("Restoring SELinux to enforcing mode");
            SELinuxUtils::SetEnforcing();
        }

        // 9. 分离进程
        process_utils_.DetachProcess(target_pid);

        return injection_success;
    }

    uint64_t Injector::CallRemoteFunction(pid_t pid, uint64_t func_addr,
                                          const std::vector<uint64_t>& args) {
        return process_utils_.CallRemoteFunction(pid, func_addr, args);
    }

    uint64_t Injector::GetRemoteAddress(pid_t pid, const std::string& module_name,
                                        const std::string& func_name) {
        LOGD("GetRemoteAddress: module=%s, function=%s", module_name.c_str(), func_name.c_str());

        uint64_t remote_base = process_utils_.GetModuleBase(pid, module_name);
        if (remote_base == 0) {
            LOGD("  Module %s not found in process %d", module_name.c_str(), pid);
            return 0;
        }

        uint64_t local_base = process_utils_.GetModuleBase(getpid(), module_name);
        if (local_base == 0) {
            LOGD("  Module %s not found in local process", module_name.c_str());
            return 0;
        }

        LOGD("  Local base: 0x%lx, Remote base: 0x%lx", local_base, remote_base);

        void* local_func = dlsym(RTLD_DEFAULT, func_name.c_str());
        if (local_func == nullptr) {
            LOGD("  Function %s not found in default libs, trying to load module", func_name.c_str());
            std::string full_module_name = module_name;
            if (module_name.find(".so") == std::string::npos) {
                full_module_name += ".so";
            }

            void* handle = dlopen(full_module_name.c_str(), RTLD_NOW | RTLD_GLOBAL);
            if (handle) {
                local_func = dlsym(handle, func_name.c_str());
                dlclose(handle);
            }
        }

        if (local_func == nullptr) {
            LOGD("  Function %s not found in module %s", func_name.c_str(), module_name.c_str());
            return 0;
        }

        uint64_t offset = (uint64_t)local_func - local_base;
        uint64_t remote_addr = remote_base + offset;

        LOGD("  Function %s: local=0x%lx, remote=0x%lx, offset=0x%lx",
             func_name.c_str(), (uint64_t)local_func, remote_addr, offset);

        return remote_addr;
    }

}