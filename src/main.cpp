#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <fstream>
#include "core/injector.h"
#include "utils/process.h"

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options] <pid> <library_path>" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help     Show this help message" << std::endl;
    std::cout << "  -v, --verbose  Enable verbose logging" << std::endl;
    std::cout << "  -w, --wait     Wait for process to appear (for process name)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " 1234 /data/local/tmp/libhook.so" << std::endl;
    std::cout << "  " << program_name << " -w com.example.app /data/local/tmp/libhook.so" << std::endl;
}

pid_t find_process_by_name(const std::string& process_name) {
    DIR* dir = opendir("/proc");
    if (!dir) {
        return -1;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (!isdigit(entry->d_name[0])) {
            continue;
        }

        pid_t pid = atoi(entry->d_name);

        char cmdline_path[256];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

        std::ifstream cmdline_file(cmdline_path);
        if (cmdline_file.is_open()) {
            std::string cmdline;
            std::getline(cmdline_file, cmdline, '\0');
            cmdline_file.close();

            if (cmdline.find(process_name) != std::string::npos) {
                closedir(dir);
                return pid;
            }
        }
    }

    closedir(dir);
    return -1;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    bool verbose = false;
    bool wait_for_process = false;
    int opt_index = 1;

    while (opt_index < argc && argv[opt_index][0] == '-') {
        std::string opt = argv[opt_index];

        if (opt == "-h" || opt == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (opt == "-v" || opt == "--verbose") {
            verbose = true;
        } else if (opt == "-w" || opt == "--wait") {
            wait_for_process = true;
        } else {
            std::cerr << "Unknown option: " << opt << std::endl;
            print_usage(argv[0]);
            return 1;
        }

        opt_index++;
    }

    if (argc - opt_index < 2) {
        std::cerr << "Error: Missing required arguments" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    std::string target = argv[opt_index];
    std::string library_path = argv[opt_index + 1];

    if (access(library_path.c_str(), F_OK) != 0) {
        std::cerr << "Error: Library file not found: " << library_path << std::endl;
        return 1;
    }

    if (geteuid() != 0) {
        std::cerr << "Error: This tool requires root privileges" << std::endl;
        std::cerr << "Please run with 'su' or 'sudo'" << std::endl;
        return 1;
    }

    pid_t target_pid;

    if (isdigit(target[0])) {
        target_pid = std::stoi(target);
    } else {
        if (wait_for_process) {
            std::cout << "Waiting for process: " << target << std::endl;
            while ((target_pid = find_process_by_name(target)) == -1) {
                usleep(500000); // 500ms
            }
            std::cout << "Process found with PID: " << target_pid << std::endl;
        } else {
            target_pid = find_process_by_name(target);
            if (target_pid == -1) {
                std::cerr << "Error: Process not found: " << target << std::endl;
                return 1;
            }
        }
    }

    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", target_pid);
    if (access(proc_path, F_OK) != 0) {
        std::cerr << "Error: Process " << target_pid << " does not exist" << std::endl;
        return 1;
    }
    utils::ProcessUtils process_utils;
    std::string arch = process_utils.GetProcessArchitecture(target_pid);
    if (arch != "arm64") {
        std::cerr << "Error: Target process is not ARM64 (detected: " << arch << ")" << std::endl;
        std::cerr << "This injector only supports ARM64 processes" << std::endl;
        return 1;
    }

    std::cout << "Target process: " << target_pid << " (" << arch << ")" << std::endl;
    std::cout << "Library path: " << library_path << std::endl;

    injector::Injector injector;

    std::cout << "Starting injection..." << std::endl;

    bool success = injector.Inject(target_pid, library_path);

    if (success) {
        std::cout << "Injection successful!" << std::endl;
        return 0;
    } else {
        std::cerr << "Injection failed!" << std::endl;
        return 1;
    }
}
