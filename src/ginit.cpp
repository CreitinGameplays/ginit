#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/reboot.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <csignal>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "network.h"
#include "debug.h"
#include "signals.h"
#include "sys_info.h"
#include "user_mgmt.h"
#include "gservice_parser.hpp"
#include "gservice_manager.hpp"

ginit::GServiceManager service_manager;

void safe_mkdir(const char* dir);

std::string trim_copy_local(const std::string& value) {
    size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string unquote_os_release_value(std::string value) {
    value = trim_copy_local(value);
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

std::map<std::string, std::string> load_os_release_fields(const std::string& path = "/etc/os-release") {
    std::map<std::string, std::string> fields;
    std::ifstream file(path);
    if (!file) return fields;

    std::string line;
    while (std::getline(file, line)) {
        line = trim_copy_local(line);
        if (line.empty() || line[0] == '#') continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim_copy_local(line.substr(0, eq));
        std::string value = unquote_os_release_value(line.substr(eq + 1));
        if (!key.empty()) fields[key] = value;
    }

    return fields;
}

std::string release_field_or(
    const std::map<std::string, std::string>& fields,
    const std::string& key,
    const std::string& fallback
) {
    auto it = fields.find(key);
    if (it == fields.end() || trim_copy_local(it->second).empty()) return fallback;
    return it->second;
}

std::string runtime_pretty_name() {
    auto fields = load_os_release_fields();
    return release_field_or(fields, "PRETTY_NAME", std::string(OS_NAME) + " " + OS_VERSION);
}

std::string to_lower_copy_local(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string find_first_existing_path(const std::vector<std::string>& candidates) {
    for (const auto& candidate : candidates) {
        if (!candidate.empty() && access(candidate.c_str(), F_OK) == 0) {
            return candidate;
        }
    }
    return "";
}

int run_helper_command(const std::string& path, const std::vector<std::string>& args) {
    pid_t pid = fork();
    if (pid < 0) {
        perror(("[GINIT] fork failed for " + path).c_str());
        return -1;
    }

    if (pid == 0) {
        std::vector<char*> exec_args;
        exec_args.reserve(args.size() + 2);
        exec_args.push_back(const_cast<char*>(path.c_str()));
        for (const auto& arg : args) {
            exec_args.push_back(const_cast<char*>(arg.c_str()));
        }
        exec_args.push_back(nullptr);
        execv(path.c_str(), exec_args.data());
        perror(("[GINIT] exec failed for " + path).c_str());
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror(("[GINIT] waitpid failed for " + path).c_str());
        return -1;
    }

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

void configure_selinux_runtime() {
    const bool is_live = access("/etc/geminios-live", F_OK) == 0;

    auto config = load_os_release_fields("/etc/selinux/config");
    std::string mode = to_lower_copy_local(release_field_or(config, "SELINUX", "disabled"));
    std::string policy_name = trim_copy_local(release_field_or(config, "SELINUXTYPE", "default"));

    if (mode == "disabled") {
        return;
    }

    safe_mkdir("/sys/fs");
    safe_mkdir("/sys/fs/selinux");

    if (mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, nullptr) != 0 && errno != EBUSY) {
        perror("[GINIT] Failed to mount /sys/fs/selinux");
        return;
    }

    const bool want_permissive = is_live || mode == "permissive";

    const std::string load_policy = find_first_existing_path({
        "/usr/sbin/load_policy",
        "/sbin/load_policy",
    });
    if (!load_policy.empty()) {
        int rc = run_helper_command(load_policy, {});
        if (rc != 0) {
            std::cerr << "[GINIT] SELinux policy load failed with exit code " << rc << std::endl;
        }
    } else {
        std::cerr << "[GINIT] SELinux requested but load_policy is not installed." << std::endl;
    }

    if (want_permissive) {
        if (is_live) {
            std::cout << "[GINIT] Live environment detected; forcing SELinux permissive mode." << std::endl;
        }
        const std::string setenforce = find_first_existing_path({
            "/usr/sbin/setenforce",
            "/sbin/setenforce",
        });
        if (!setenforce.empty()) {
            int rc = run_helper_command(setenforce, {"0"});
            if (rc != 0) {
                std::cerr << "[GINIT] Failed to switch SELinux to permissive mode (exit " << rc << ")." << std::endl;
            }
        }
    }

    const std::string file_contexts = find_first_existing_path({
        "/etc/selinux/" + policy_name + "/contexts/files/file_contexts",
        "/etc/selinux/default/contexts/files/file_contexts",
        "/etc/selinux/targeted/contexts/files/file_contexts",
    });
    const std::vector<std::string> relabel_paths = {
        "/bin", "/boot", "/etc", "/home", "/lib", "/lib64",
        "/opt", "/root", "/sbin", "/srv", "/usr", "/var"
    };

    if (access("/.autorelabel", F_OK) == 0 && !file_contexts.empty()) {
        const std::string setfiles = find_first_existing_path({
            "/usr/sbin/setfiles",
            "/sbin/setfiles",
        });
        if (!setfiles.empty()) {
            std::vector<std::string> args = {"-F", file_contexts};
            for (const auto& path : relabel_paths) {
                if (access(path.c_str(), F_OK) == 0) args.push_back(path);
            }

            int rc = run_helper_command(setfiles, args);
            if (rc == 0) {
                unlink("/.autorelabel");
                std::cout << "[GINIT] Completed SELinux relabel pass." << std::endl;
            } else {
                std::cerr << "[GINIT] SELinux relabel pass failed with exit code " << rc << std::endl;
            }
        }
    }

    const std::string restorecon = find_first_existing_path({
        "/usr/sbin/restorecon",
        "/sbin/restorecon",
    });
    if (!restorecon.empty()) {
        std::vector<std::string> args = {
            "-RF",
            "/dev",
            "/run",
            "/tmp",
            "/var/log",
            "/var/tmp",
            "/var/lib",
            "/home",
            "/root",
            "/etc",
        };
        int rc = run_helper_command(restorecon, args);
        if (rc != 0) {
            std::cerr << "[GINIT] restorecon failed with exit code " << rc << std::endl;
        }
    }
}

// Mount filesystems and ensure target directory exists
void mount_fs(const char* source, const char* target, const char* fs_type) {
    mkdir(target, 0755);
    if (mount(source, target, fs_type, 0, NULL) == 0) {
        std::cout << "[OK] Mounted " << target << std::endl;
    } else {
        if (errno == EBUSY) {
            std::cout << "[OK] " << target << " already mounted" << std::endl;
        } else {
            perror((std::string("[ERR] Failed to mount ") + target).c_str());
        }
    }
}

// Ensure FHS directory structure exists
void safe_mkdir(const char* dir) {
    if (mkdir(dir, 0755) != 0) {
        if (errno != EEXIST) {
            perror((std::string("[GINIT] Failed to create ") + dir).c_str());
        }
    }
}

void ensure_fhs() {
    const char* dirs[] = {
        "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/media", 
        "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", 
        "/sys", "/tmp", "/usr", "/usr/bin", "/usr/lib", "/usr/lib/locale", "/usr/lib/gconv", "/usr/local", 
        "/usr/share", "/var", "/var/lib", "/var/log", "/var/tmp", "/var/repo",
        "/sys/fs", "/sys/fs/selinux",
        "/run/lock", "/run/user", "/run/systemd", "/run/systemd/inhibit", "/run/systemd/seats",
        "/run/systemd/sessions", "/run/systemd/users", "/var/lib/elogind",
        "/usr/share/X11", "/usr/share/X11/xkb", "/usr/share/X11/xkb/compiled"
    };
    
    for (const char* d : dirs) {
        safe_mkdir(d);
    }
    
    chmod("/tmp", 01777);
    chmod("/var/tmp", 01777);
    chmod("/root", 0700);
}

// Generate system information files for other applications (like neofetch, gemfetch)
void generate_os_release() {
    auto release = load_os_release_fields();
    if (release.empty()) {
        release["NAME"] = OS_NAME;
        release["VERSION"] = OS_VERSION;
        release["ID"] = OS_ID;
        release["ID_LIKE"] = OS_ID_LIKE;
        release["PRETTY_NAME"] = std::string(OS_NAME) + " " + OS_VERSION;
        release["VERSION_ID"] = OS_VERSION_ID;
        release["VERSION_CODENAME"] = OS_CODENAME;
        release["ANSI_COLOR"] = OS_ANSI_COLOR;
        release["HOME_URL"] = "https://github.com/CreitinGameplays/geminios";
        release["SUPPORT_URL"] = "https://github.com/CreitinGameplays/geminios/issues";
        release["BUG_REPORT_URL"] = "https://github.com/CreitinGameplays/geminios/issues";

        std::ofstream f("/etc/os-release");
        if (f) {
            f << "NAME=\"" << release["NAME"] << "\"\n";
            f << "VERSION=\"" << release["VERSION"] << "\"\n";
            f << "ID=" << release["ID"] << "\n";
            f << "ID_LIKE=\"" << release["ID_LIKE"] << "\"\n";
            f << "PRETTY_NAME=\"" << release["PRETTY_NAME"] << "\"\n";
            f << "VERSION_ID=\"" << release["VERSION_ID"] << "\"\n";
            f << "VERSION_CODENAME=\"" << release["VERSION_CODENAME"] << "\"\n";
            f << "ANSI_COLOR=\"" << release["ANSI_COLOR"] << "\"\n";
            f << "HOME_URL=\"" << release["HOME_URL"] << "\"\n";
            f << "SUPPORT_URL=\"" << release["SUPPORT_URL"] << "\"\n";
            f << "BUG_REPORT_URL=\"" << release["BUG_REPORT_URL"] << "\"\n";
            f.close();
            std::cout << "[GINIT] Generated fallback /etc/os-release" << std::endl;
        }
    }

    std::string pretty_name = release_field_or(release, "PRETTY_NAME", std::string(OS_NAME) + " " + OS_VERSION);
    std::string version_id = release_field_or(release, "VERSION_ID", OS_VERSION_ID);
    std::string codename = release_field_or(release, "VERSION_CODENAME", OS_CODENAME);

    std::ofstream lsb("/etc/lsb-release");
    if (lsb) {
        lsb << "DISTRIB_ID=" << release_field_or(release, "NAME", OS_NAME) << "\n";
        lsb << "DISTRIB_RELEASE=" << version_id << "\n";
        lsb << "DISTRIB_CODENAME=" << codename << "\n";
        lsb << "DISTRIB_DESCRIPTION=\"" << pretty_name << "\"\n";
        lsb.close();
        std::cout << "[GINIT] Generated /etc/lsb-release" << std::endl;
    }

    if (access("/etc/hostname", F_OK) == -1) {
        std::ofstream hn("/etc/hostname");
        if (hn) {
            hn << "geminios-pc\n";
            hn.close();
            sethostname("geminios-pc", 11);
            std::cout << "[GINIT] Set hostname to geminios-pc" << std::endl;
        }
    } else {
        std::ifstream hn("/etc/hostname");
        std::string name;
        if (hn >> name) sethostname(name.c_str(), name.length());
    }

    std::ofstream issue("/etc/issue");
    if (issue) {
        issue << pretty_name << "\n\\l\n\n";
        issue.close();
    }
}

// Map to track TTY Supervisor PIDs: PID -> TTY Device Path
std::map<pid_t, std::string> g_tty_pids;

pid_t spawn_getty(const std::string& tty, const std::string& autologin_user = "") {
    pid_t pid = fork();
    if (pid == 0) {
        // Child: Exec getty
        if (!autologin_user.empty()) {
             execl("/sbin/getty", "getty", tty.c_str(), autologin_user.c_str(), nullptr);
        } else {
             execl("/sbin/getty", "getty", tty.c_str(), nullptr);
        }
        perror("execv /sbin/getty");
        exit(1);
    }
    return pid;
}

void show_help() {
    std::cout << "GeminiOS Init System (ginit) CLI" << std::endl;
    std::cout << "Usage: ginit <command> [service]" << std::endl;
    std::cout << "\nCommands:" << std::endl;
    std::cout << "  status [service]   Show status of all services or a specific one" << std::endl;
    std::cout << "  start <service>    Start a service" << std::endl;
    std::cout << "  stop <service>     Stop a service" << std::endl;
    std::cout << "  restart <service>  Restart a service" << std::endl;
    std::cout << "  enable <service>   Enable a service to start at boot" << std::endl;
    std::cout << "  disable <service>  Disable a service from starting at boot" << std::endl;
    std::cout << "  help               Show this help message" << std::endl;
}

void handle_signal(int sig) {
    if (sig == SIGINT) {
        std::cerr << "[GINIT] Rebooting..." << std::endl;
        sync();
        reboot(RB_AUTOBOOT);
    } else if (sig == SIGTERM || sig == SIGPWR) {
        std::cerr << "[GINIT] Powering off..." << std::endl;
        sync();
        reboot(RB_POWER_OFF);
    }
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (getpid() == 1) {
        setenv("PATH", "/bin:/usr/bin:/sbin:/usr/sbin:/bin/apps/system:/bin/apps", 1);
        signal(SIGINT, handle_signal);
        signal(SIGTERM, handle_signal);
        signal(SIGPWR, handle_signal);
    }

    if (getpid() != 1) {
        if (argc < 2) {
            show_help();
            return 1;
        }

        std::string cmd = argv[1];
        if (cmd == "help" || cmd == "--help" || cmd == "-h") {
            show_help();
            return 0;
        }

        std::string service = (argc > 2) ? argv[2] : "";
        
        // Commands that REQUIRE a service name
        if (cmd == "start" || cmd == "stop" || cmd == "restart" || cmd == "enable" || cmd == "disable") {
            if (service.empty()) {
                std::cerr << "Error: Command '" << cmd << "' requires a service name." << std::endl;
                std::cerr << "Usage: ginit " << cmd << " <service>" << std::endl;
                return 1;
            }
        }

        if (cmd == "status" || cmd == "start" || cmd == "stop" || cmd == "restart" || cmd == "enable" || cmd == "disable") {
            ginit::GServiceManager::send_command(cmd + " " + service);
            return 0;
        }

        if (cmd == "--configure-network") {
            return ConfigureNetwork();
        }

        std::cerr << "Unknown command: " << cmd << std::endl;
        show_help();
        return 1;
    }

    std::cout << "\033[2J\033[1;1H";
    std::cout << "Welcome to " << runtime_pretty_name() << std::endl;
    
mount_fs("none", "/proc", "proc");
mount_fs("none", "/sys", "sysfs");
mount_fs("devtmpfs", "/dev", "devtmpfs");
mount_fs("devpts", "/dev/pts", "devpts");
mount_fs("tmpfs", "/dev/shm", "tmpfs");
mount_fs("tmpfs", "/tmp", "tmpfs");
mount_fs("tmpfs", "/run", "tmpfs");
mount_fs("tmpfs", "/var/log", "tmpfs");
mount_fs("tmpfs", "/var/tmp", "tmpfs");
mount_fs("tmpfs", "/usr/share/X11/xkb/compiled", "tmpfs");

ensure_fhs();

mkdir("/var/lib/dbus", 0755);
mkdir("/run/dbus", 0755);

symlink("/proc/self/fd", "/dev/fd");
symlink("/proc/self/fd/0", "/dev/stdin");
symlink("/proc/self/fd/1", "/dev/stdout");
symlink("/proc/self/fd/2", "/dev/stderr");

UserMgmt::initialize_defaults();
generate_os_release();

// Ensure service directories exist
safe_mkdir("/etc/ginit");
safe_mkdir("/etc/ginit/services");
safe_mkdir("/etc/ginit/services/system");
safe_mkdir("/usr/lib/ginit");
safe_mkdir("/usr/lib/ginit/services");
safe_mkdir("/run/systemd");
safe_mkdir("/run/systemd/inhibit");
safe_mkdir("/run/systemd/seats");
safe_mkdir("/run/systemd/sessions");
safe_mkdir("/run/systemd/users");
safe_mkdir("/run/user");
safe_mkdir("/var/lib/elogind");

configure_selinux_runtime();

// Copy default services to system directory if not present
// This is a bit of a hack for first boot, but okay for now.
// In a real OS, this would be handled by the package manager.

std::cerr << "[GINIT] Loading system services..." << std::endl;
service_manager.load_services_from_dir("/usr/lib/ginit/services");
service_manager.load_services_from_dir("/etc/ginit/services/system");

// Explicitly enable core services for boot
service_manager.enable_service("udevd");
service_manager.enable_service("udev-trigger");
service_manager.enable_service("udev-settle");
service_manager.enable_service("fuse-device");
service_manager.enable_service("network");
service_manager.enable_service("dbus");
service_manager.enable_service("elogind");

std::cerr << "[GINIT] Starting system services..." << std::endl;
service_manager.start_enabled_services();
service_manager.run_ipc_server();

std::vector<std::string> terminals = {"/dev/tty1", "/dev/tty2", "/dev/tty3", "/dev/ttyS0"};

// Check if we are in Live Environment
bool is_live = (access("/etc/geminios-live", F_OK) == 0);

for (const auto& tty : terminals) {
    pid_t pid;
    if (is_live) {
         // Autologin as root on all terminals for Live CD
         pid = spawn_getty(tty, "root");
    } else {
         // Standard Login Prompt for Installed System
         pid = spawn_getty(tty);
    }

    if (pid > 0) {
        g_tty_pids[pid] = tty;
    }
}

// Supervisor Loop: Reap and respawn processes
while (true) {
    int status;
    pid_t pid = wait(&status);

    if (pid > 0) {
        if (service_manager.is_managed_process(pid)) {
            service_manager.handle_process_death(pid, status);
        } else {
            auto it = g_tty_pids.find(pid);
            if (it != g_tty_pids.end()) {
                std::string tty = it->second;
                g_tty_pids.erase(it);
                
                // std::cerr << "[GINIT] TTY " << tty << " respawning..." << std::endl;
                
                pid_t new_pid;
                if (is_live) {
                    new_pid = spawn_getty(tty, "root");
                } else {
                    new_pid = spawn_getty(tty);
                }

                if (new_pid > 0) {
                    g_tty_pids[new_pid] = tty;
                }
            }
        }
    }
}
}
