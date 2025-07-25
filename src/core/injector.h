#pragma once

#include <string>
#include <vector>
#include <map>
#include "../utils/types.h"
#include "../utils/process.h"

namespace injector {

    class Injector {
    public:
        Injector();
        ~Injector();

        bool Inject(pid_t target_pid, const std::string& library_path);

    private:
        uint64_t CallRemoteFunction(pid_t pid, uint64_t func_addr,
                                    const std::vector<uint64_t>& args);

        uint64_t GetRemoteAddress(pid_t pid, const std::string& module_name,
                                  const std::string& func_name);

    private:
        std::map<std::string, uint64_t> module_cache_;
        bool selinux_enforcing_;
        utils::ProcessUtils process_utils_;
    };

}
