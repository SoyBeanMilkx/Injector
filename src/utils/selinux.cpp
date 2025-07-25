#include "selinux.h"
#include "logger.h"
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <errno.h>

namespace utils {

    bool SELinuxUtils::IsEnforcing() {
        return GetEnforceStatus() == 1;
    }

    bool SELinuxUtils::IsPermissive() {
        return GetEnforceStatus() == 0;
    }

    bool SELinuxUtils::IsDisabled() {
        return GetEnforceStatus() == -1;
    }

    bool SELinuxUtils::SetEnforcing() {
        LOGI("Setting SELinux to enforcing mode");
        return SetEnforceStatus(1);
    }

    bool SELinuxUtils::SetPermissive() {
        LOGI("Setting SELinux to permissive mode");
        return SetEnforceStatus(0);
    }

    int SELinuxUtils::GetEnforceStatus() {
        LOGD("Checking SELinux enforce status...");

        std::ifstream enforce_file("/sys/fs/selinux/enforce");
        if (!enforce_file.is_open()) {
            LOGD("  /sys/fs/selinux/enforce not found, trying old path...");
            // 尝试旧路径
            enforce_file.open("/selinux/enforce");
            if (!enforce_file.is_open()) {
                LOGD("  SELinux appears to be disabled");
                return -1;
            }
        }

        int status;
        enforce_file >> status;
        enforce_file.close();

        LOGD("  SELinux enforce status: %d (%s)", status,
             status == 1 ? "enforcing" : status == 0 ? "permissive" : "unknown");

        return status;
    }

    bool SELinuxUtils::SetEnforceStatus(int status) {
        int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
        if (fd < 0) {
            // 尝试旧路径
            fd = open("/selinux/enforce", O_WRONLY);
            if (fd < 0) {
                LOGE("Failed to open SELinux enforce file: %s", strerror(errno));
                return false;
            }
        }

        char status_str[2];
        snprintf(status_str, sizeof(status_str), "%d", status);

        ssize_t written = write(fd, status_str, 1);
        close(fd);

        if (written != 1) {
            LOGE("Failed to write SELinux enforce status: %s", strerror(errno));
            return false;
        }

        LOGI("SELinux enforce status set to %d", status);
        return true;
    }

    std::string SELinuxUtils::GetProcessContext(pid_t pid) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            LOGE("Failed to open %s: %s", path, strerror(errno));
            return "";
        }

        char context[256];
        ssize_t len = read(fd, context, sizeof(context) - 1);
        close(fd);

        if (len > 0) {
            context[len] = '\0';
            if (context[len - 1] == '\n') {
                context[len - 1] = '\0';
            }
            return std::string(context);
        }

        return "";
    }

    bool SELinuxUtils::SetProcessContext(pid_t pid, const std::string& context) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);

        int fd = open(path, O_WRONLY);
        if (fd < 0) {
            LOGE("Failed to open %s: %s", path, strerror(errno));
            return false;
        }

        ssize_t written = write(fd, context.c_str(), context.length());
        close(fd);

        if (written < 0) {
            LOGE("Failed to write SELinux context: %s", strerror(errno));
            return false;
        }

        LOGI("Set process %d context to: %s", pid, context.c_str());
        return true;
    }

}