#include "user_mgmt.h"

#include <cerrno>
#include <crypt.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

struct BootstrapAccount {
    const char* username;
    uid_t uid;
    gid_t gid;
    const char* gecos;
    const char* home;
    const char* shell;
};

constexpr BootstrapAccount kServiceAccounts[] = {
    {"messagebus", 18, 18, "D-Bus Message Daemon User", "/var/run/dbus", "/bin/false"},
    {"lightdm", 620, 620, "Light Display Manager", "/var/lib/lightdm", "/bin/false"},
    {"sddm", 621, 621, "Simple Desktop Display Manager", "/var/lib/sddm", "/bin/false"},
};

std::string default_root_hash() {
    // A fixed salt keeps the bootstrap helper tiny while still storing a real
    // SHA-512 crypt hash instead of a plaintext password in /etc/shadow.
    static constexpr const char* kSalt = "$6$geminios$";
    char* hashed = crypt("root", kSalt);
    if (!hashed) {
        std::cerr << "[INIT] crypt() failed while creating default root password: "
                  << std::strerror(errno) << std::endl;
        return "!";
    }
    return hashed;
}

bool file_has_entry(const char* path, const std::string& name) {
    std::ifstream file(path);
    if (!file) {
        return false;
    }
    const std::string prefix = name + ":";
    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind(prefix, 0) == 0) {
            return true;
        }
    }
    return false;
}

void append_line_if_missing(const char* path, const std::string& name, const std::string& line) {
    if (file_has_entry(path, name)) {
        return;
    }

    std::ofstream file(path, std::ios::app);
    if (!file) {
        std::cerr << "[INIT] Failed to append missing entry for " << name
                  << " to " << path << std::endl;
        return;
    }
    file << line << "\n";
}

bool ensure_directory_tree(const std::string& path, mode_t mode) {
    if (path.empty() || path == "/") {
        return true;
    }

    size_t position = 1;
    while (true) {
        position = path.find('/', position);
        const std::string component =
            (position == std::string::npos) ? path : path.substr(0, position);
        if (!component.empty() && mkdir(component.c_str(), mode) != 0 && errno != EEXIST) {
            std::cerr << "[INIT] mkdir(" << component << ") failed: "
                      << std::strerror(errno) << std::endl;
            return false;
        }
        if (position == std::string::npos) {
            break;
        }
        ++position;
    }

    return true;
}

void ensure_owned_directory(const std::string& path, mode_t mode, uid_t uid, gid_t gid) {
    if (!ensure_directory_tree(path, mode)) {
        return;
    }

    if (chmod(path.c_str(), mode) != 0 && errno != ENOENT) {
        std::cerr << "[INIT] chmod(" << path << ") failed: "
                  << std::strerror(errno) << std::endl;
    }
    if (chown(path.c_str(), uid, gid) != 0) {
        std::cerr << "[INIT] chown(" << path << ") failed: "
                  << std::strerror(errno) << std::endl;
    }
}

} // namespace

void UserMgmt::initialize_defaults() {
    if (access("/etc/passwd", F_OK) != 0) {
        std::cout << "[INIT] Creating default /etc/passwd..." << std::endl;
        std::ofstream passwd("/etc/passwd");
        if (passwd) {
            passwd << "root:x:0:0:System Administrator:/root:/bin/bash\n";
            for (const auto& account : kServiceAccounts) {
                passwd << account.username << ":x:" << account.uid << ":" << account.gid << ":"
                       << account.gecos << ":" << account.home << ":" << account.shell << "\n";
            }
        } else {
            std::cerr << "[INIT] Failed to create /etc/passwd" << std::endl;
        }
    }

    if (access("/etc/shadow", F_OK) != 0) {
        std::cout << "[INIT] Creating default /etc/shadow..." << std::endl;
        std::ofstream shadow("/etc/shadow");
        if (shadow) {
            shadow << "root:" << default_root_hash() << ":19000:0:99999:7:::" << "\n";
            for (const auto& account : kServiceAccounts) {
                shadow << account.username << ":!:19000:0:99999:7:::" << "\n";
            }
            shadow.close();
            if (chmod("/etc/shadow", 0600) != 0) {
                std::cerr << "[INIT] chmod(/etc/shadow) failed: " << std::strerror(errno) << std::endl;
            }
        } else {
            std::cerr << "[INIT] Failed to create /etc/shadow" << std::endl;
        }
    }

    if (access("/etc/group", F_OK) != 0) {
        std::cout << "[INIT] Creating default /etc/group..." << std::endl;
        std::ofstream group("/etc/group");
        if (group) {
            group << "root:x:0:\n";
            group << "sudo:x:27:root\n";
            group << "users:x:100:\n";
            for (const auto& account : kServiceAccounts) {
                group << account.username << ":x:" << account.gid << ":\n";
            }
        } else {
            std::cerr << "[INIT] Failed to create /etc/group" << std::endl;
        }
    }

    for (const auto& account : kServiceAccounts) {
        append_line_if_missing("/etc/passwd", account.username,
                               std::string(account.username) + ":x:" + std::to_string(account.uid) +
                                   ":" + std::to_string(account.gid) + ":" + account.gecos + ":" +
                                   account.home + ":" + account.shell);
        append_line_if_missing("/etc/shadow", account.username,
                               std::string(account.username) + ":!:19000:0:99999:7:::");
        append_line_if_missing("/etc/group", account.username,
                               std::string(account.username) + ":x:" + std::to_string(account.gid) +
                                   ":");
    }

    ensure_owned_directory("/root", 0700, 0, 0);
    ensure_owned_directory("/home", 0755, 0, 0);
    for (const auto& account : kServiceAccounts) {
        ensure_owned_directory(account.home, 0755, account.uid, account.gid);
    }
}
