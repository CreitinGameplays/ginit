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

struct BootstrapGroup {
    const char* name;
    gid_t gid;
    const char* members;
};

constexpr BootstrapGroup kBaseGroups[] = {
    {"root", 0, ""},
    {"daemon", 1, ""},
    {"bin", 2, ""},
    {"sys", 3, ""},
    {"adm", 4, ""},
    {"tty", 5, ""},
    {"disk", 6, ""},
    {"lp", 7, ""},
    {"mail", 8, ""},
    {"news", 9, ""},
    {"uucp", 10, ""},
    {"man", 12, ""},
    {"proxy", 13, ""},
    {"kmem", 15, ""},
    {"dialout", 20, ""},
    {"fax", 21, ""},
    {"voice", 22, ""},
    {"cdrom", 24, ""},
    {"floppy", 25, ""},
    {"tape", 26, ""},
    {"sudo", 27, "root"},
    {"audio", 29, ""},
    {"dip", 30, ""},
    {"www-data", 33, ""},
    {"backup", 34, ""},
    {"operator", 37, ""},
    {"list", 38, ""},
    {"irc", 39, ""},
    {"src", 40, ""},
    {"shadow", 42, ""},
    {"utmp", 43, ""},
    {"video", 44, ""},
    {"sasl", 45, ""},
    {"plugdev", 46, ""},
    {"staff", 50, ""},
    {"games", 60, ""},
    {"kvm", 78, ""},
    {"power", 98, ""},
    {"storage", 99, ""},
    {"users", 100, ""},
    {"input", 101, ""},
    {"render", 102, ""},
    {"sgx", 103, ""},
    {"netdev", 106, ""},
    {"systemd-journal", 190, ""},
    {"nogroup", 65534, ""},
};

constexpr BootstrapAccount kBaseAccounts[] = {
    {"daemon", 1, 1, "daemon", "/usr/sbin", "/usr/sbin/nologin"},
    {"bin", 2, 2, "bin", "/bin", "/usr/sbin/nologin"},
    {"sys", 3, 3, "sys", "/dev", "/usr/sbin/nologin"},
    {"sync", 4, 65534, "sync", "/bin", "/bin/sync"},
    {"games", 5, 60, "games", "/usr/games", "/usr/sbin/nologin"},
    {"man", 6, 12, "man", "/var/cache/man", "/usr/sbin/nologin"},
    {"lp", 7, 7, "lp", "/var/spool/lpd", "/usr/sbin/nologin"},
    {"mail", 8, 8, "mail", "/var/mail", "/usr/sbin/nologin"},
    {"news", 9, 9, "news", "/var/spool/news", "/usr/sbin/nologin"},
    {"uucp", 10, 10, "uucp", "/var/spool/uucp", "/usr/sbin/nologin"},
    {"proxy", 13, 13, "proxy", "/bin", "/usr/sbin/nologin"},
    {"www-data", 33, 33, "www-data", "/var/www", "/usr/sbin/nologin"},
    {"backup", 34, 34, "backup", "/var/backups", "/usr/sbin/nologin"},
    {"list", 38, 38, "Mailing List Manager", "/var/list", "/usr/sbin/nologin"},
    {"irc", 39, 39, "ircd", "/run/ircd", "/usr/sbin/nologin"},
    {"_apt", 42, 65534, "", "/nonexistent", "/usr/sbin/nologin"},
    {"nobody", 65534, 65534, "nobody", "/nonexistent", "/usr/sbin/nologin"},
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
            for (const auto& account : kBaseAccounts) {
                passwd << account.username << ":x:" << account.uid << ":" << account.gid << ":"
                       << account.gecos << ":" << account.home << ":" << account.shell << "\n";
            }
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
            for (const auto& account : kBaseAccounts) {
                shadow << account.username << ":!:19000:0:99999:7:::" << "\n";
            }
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
            for (const auto& entry : kBaseGroups) {
                group << entry.name << ":x:" << entry.gid << ":" << entry.members << "\n";
            }
            for (const auto& account : kServiceAccounts) {
                group << account.username << ":x:" << account.gid << ":\n";
            }
        } else {
            std::cerr << "[INIT] Failed to create /etc/group" << std::endl;
        }
    }

    for (const auto& account : kBaseAccounts) {
        append_line_if_missing("/etc/passwd", account.username,
                               std::string(account.username) + ":x:" + std::to_string(account.uid) +
                                   ":" + std::to_string(account.gid) + ":" + account.gecos + ":" +
                                   account.home + ":" + account.shell);
        append_line_if_missing("/etc/shadow", account.username,
                               std::string(account.username) + ":!:19000:0:99999:7:::");
    }
    for (const auto& entry : kBaseGroups) {
        append_line_if_missing("/etc/group", entry.name,
                               std::string(entry.name) + ":x:" + std::to_string(entry.gid) +
                                   ":" + entry.members);
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
