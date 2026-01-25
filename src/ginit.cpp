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
    std::ofstream f("/etc/os-release");
    if (f) {
        f << "NAME=\"" << OS_NAME << "\"\n";
        f << "VERSION=\"" << OS_VERSION << " (" << OS_CODENAME << ")\"\n";
        f << "ID=" << OS_ID << "\n";
        f << "ID_LIKE=" << OS_ID_LIKE << "\n";
        f << "PRETTY_NAME=\"" << OS_NAME << " " << OS_VERSION << " (" << OS_CODENAME << ")\"\n";
        f << "VERSION_ID=\"" << OS_VERSION << "\"\n";
        f << "VERSION_CODENAME=" << OS_CODENAME << "\n";
        f << "ANSI_COLOR=\"" << OS_ANSI_COLOR << "\"\n";
        f << "HOME_URL=\"https://github.com/CreitinGameplays/geminios\"\n";
        f << "SUPPORT_URL=\"https://github.com/CreitinGameplays/geminios/issues\"\n";
        f << "BUG_REPORT_URL=\"https://github.com/CreitinGameplays/geminios/issues\"\n";
        f.close();
        std::cout << "[GINIT] Generated /etc/os-release" << std::endl;
    }

    std::ofstream lsb("/etc/lsb-release");
    if (lsb) {
        lsb << "DISTRIB_ID=" << OS_NAME << "\n";
        lsb << "DISTRIB_RELEASE=" << OS_VERSION << "\n";
        lsb << "DISTRIB_CODENAME=" << OS_CODENAME << "\n";
        lsb << "DISTRIB_DESCRIPTION=\"" << OS_NAME << " " << OS_VERSION << " (" << OS_CODENAME << ")\"\n";
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
        issue << OS_NAME << " " << OS_VERSION << " (" << OS_CODENAME << ") \n \\l\n\n";
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
    std::cout << "Welcome to " << OS_NAME << " " << OS_VERSION << std::endl;     
    
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
service_manager.enable_service("network");
service_manager.enable_service("dbus");

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
