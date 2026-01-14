#include "gservice_manager.hpp"
#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <cstring>
#include <algorithm>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <thread>
#include <sstream>
#include <pwd.h>
#include <grp.h>
#include <sys/prctl.h>

namespace ginit {

// Helper to parse duration strings like "5s", "100ms" into microseconds
unsigned long parse_duration(const std::string& str) {
    if (str.empty()) return 0;
    
    unsigned long val = 0;
    std::string unit;
    
    size_t i = 0;
    while (i < str.length() && isdigit(str[i])) {
        val = val * 10 + (str[i] - '0');
        i++;
    }
    
    if (i < str.length()) unit = str.substr(i);
    
    if (unit == "ms") return val * 1000;
    if (unit == "s") return val * 1000000;
    if (unit == "m") return val * 60 * 1000000;
    if (unit == "h") return val * 3600 * 1000000;
    
    // Default to seconds if just a number, or treat as seconds if unknown
    return val * 1000000;
}

std::string get_socket_path() {
    const char* env_path = getenv("GINIT_SOCK");
    if (env_path) return env_path;
    return "/run/ginit.sock";
}

GServiceManager::GServiceManager() {}

void GServiceManager::load_services_from_dir(const std::string& dir) {
    DIR* d = opendir(dir.c_str());
    if (!d) return;

    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string filename = entry->d_name;
        if (filename.size() > 9 && filename.substr(filename.size() - 9) == ".gservice") {
            auto config = GServiceParser::parse_file(dir + "/" + filename);
            if (config) {
                std::string name = config->name;
                services[name].config = std::move(config);
                services[name].enabled = true; 
                std::cout << "[GSERVICE] Loaded " << name << " from " << filename << std::endl;
            }
        }
    }
    closedir(d);
}

void GServiceManager::setup_environment(const GService& config) {
    // Set variables from config
    for (const auto& var : config.env.vars) {
        setenv(var.first.c_str(), var.second.c_str(), 1);
    }
    
    // Set working directory
    if (!config.process.work_dir.empty()) {
        if (chdir(config.process.work_dir.c_str()) != 0) {
            perror("chdir");
        }
    }
}

void GServiceManager::setup_security(const GService& config) {
    if (!config.process.user.empty()) {
        struct passwd* pwd = getpwnam(config.process.user.c_str());
        if (pwd) {
            if (setgid(pwd->pw_gid) != 0) perror("setgid");
            if (initgroups(config.process.user.c_str(), pwd->pw_gid) != 0) perror("initgroups");
            
            if (!config.process.group.empty()) {
                struct group* grp = getgrnam(config.process.group.c_str());
                if (grp) {
                     if (setgid(grp->gr_gid) != 0) perror("setgid group");
                }
            }
            
            if (setuid(pwd->pw_uid) != 0) perror("setuid");
        } else {
             std::cerr << "[GSERVICE] User " << config.process.user << " not found!" << std::endl;
        }
    } else if (!config.process.group.empty()) {
         struct group* grp = getgrnam(config.process.group.c_str());
         if (grp) {
             if (setgid(grp->gr_gid) != 0) perror("setgid only");
         }
    }

    if (config.security.no_new_privileges) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            perror("prctl(NO_NEW_PRIVS)");
        }
    }
}

pid_t GServiceManager::spawn_process(const GService& config) {
    // Prepare logging
    std::string log_dir = "/var/log/ginit";
    mkdir(log_dir.c_str(), 0755);
    std::string log_file = log_dir + "/" + config.name + ".log";

    // Handle start_pre if it exists
    if (!config.process.commands.start_pre.empty()) {
        std::cout << "[GSERVICE] Running start_pre for " << config.name << std::endl;
        
        pid_t pre_pid = fork();
        if (pre_pid == 0) {
            // Child for start_pre
            int log_fd = open(log_file.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (log_fd >= 0) {
                dup2(log_fd, STDOUT_FILENO);
                dup2(log_fd, STDERR_FILENO);
                close(log_fd);
            }
            
            std::string cmd = config.process.commands.start_pre;
            execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
            perror("exec start_pre");
            exit(127);
        } else if (pre_pid > 0) {
            int status;
            waitpid(pre_pid, &status, 0);
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                 std::cerr << "[GSERVICE] start_pre failed for " << config.name << std::endl;
                 return -1; 
            }
        }
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child process

        // Redirect Output
        int log_fd = open(log_file.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }

        setup_environment(config);
        setup_security(config);
        
        // Execute start command
        std::string cmd = config.process.commands.start;
        execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
        
        perror("exec /bin/sh");
        exit(1);
    }
    return pid;
}

std::string GServiceManager::start_service(const std::string& name) {
    if (services.find(name) == services.end()) {
        // Try to load from available if not already loaded
        std::string path = AVAILABLE_SERVICES_DIR + "/" + name + ".gservice";
        if (access(path.c_str(), F_OK) == 0) {
            auto config = GServiceParser::parse_file(path);
            if (config) {
                services[name].config = std::move(config);
                services[name].enabled = false;
            }
        } else {
            return "Error: Service '" + name + "' not found.\n";
        }
    }

    auto& s = services[name];
    if (s.running) return "Service '" + name + "' is already running (PID " + std::to_string(s.pid) + ").\n";

    std::cout << "[GSERVICE] Starting " << name << "..." << std::endl;
    s.pid = spawn_process(*(s.config));
    if (s.pid > 0) {
        s.running = true;
        pid_to_name[s.pid] = name;
        return "Started " + name + " (PID " + std::to_string(s.pid) + ").\n";
    }
    return "Failed to start " + name + ".\n";
}

std::string GServiceManager::stop_service(const std::string& name) {
    if (services.find(name) == services.end()) return "Error: Service '" + name + "' not found.\n";
    auto& s = services[name];
    if (!s.running) return "Service '" + name + "' is not running.\n";

    std::cout << "[GSERVICE] Stopping " << name << " (PID " << s.pid << ")..." << std::endl;
    kill(s.pid, SIGTERM);
    
    // Simple wait (non-blocking attempt)
    // The main loop handles the actual reaping, but we can give it a moment
    usleep(100000); 

    return "Signal SIGTERM sent to " + name + " (PID " + std::to_string(s.pid) + ").\n";
}

std::string GServiceManager::restart_service(const std::string& name) {
    std::string stop_msg = stop_service(name);
    // Wait a bit for cleanup
    usleep(500000);
    std::string start_msg = start_service(name);
    return stop_msg + start_msg;
}

std::string GServiceManager::enable_service(const std::string& name) {
    std::string src = AVAILABLE_SERVICES_DIR + "/" + name + ".gservice";
    std::string dest = SYSTEM_SERVICES_DIR + "/" + name + ".gservice";
    
    mkdir("/etc/ginit", 0755);
    mkdir(SYSTEM_SERVICES_DIR.c_str(), 0755);

    if (access(src.c_str(), F_OK) != 0) {
        return "Error: Service '" + name + "' not available to enable.\n";
    }

    if (symlink(src.c_str(), dest.c_str()) != 0) {
        if (errno == EEXIST) return "Service '" + name + "' is already enabled.\n";
        perror("symlink");
        return "Failed to enable " + name + ".\n";
    } else {
        std::cout << "[GSERVICE] Enabled " << name << std::endl;
        if (services.count(name)) services[name].enabled = true;
        return "Enabled " + name + ".\n";
    }
}

std::string GServiceManager::disable_service(const std::string& name) {
    std::string dest = SYSTEM_SERVICES_DIR + "/" + name + ".gservice";
    if (unlink(dest.c_str()) != 0) {
        if (errno == ENOENT) return "Service '" + name + "' is not enabled.\n";
        perror("unlink");
        return "Failed to disable " + name + ".\n";
    } else {
        std::cout << "[GSERVICE] Disabled " << name << std::endl;
        if (services.count(name)) services[name].enabled = false;
        return "Disabled " + name + ".\n";
    }
}

void GServiceManager::start_enabled_services() {
    for (auto& pair : services) {
        if (pair.second.enabled && !pair.second.running) {
            start_service(pair.first);
        }
    }
}

void GServiceManager::handle_process_death(pid_t pid, int status) {
    if (pid_to_name.find(pid) == pid_to_name.end()) return;

    std::string name = pid_to_name[pid];
    auto& s = services[name];
    s.running = false;
    pid_to_name.erase(pid);

    std::cout << "[GSERVICE] Service " << name << " (pid " << pid << ") exited with status " << status << std::endl;

    // Handle restart delay
    unsigned long delay = parse_duration(s.config->process.lifecycle.restart_delay);
    if (delay > 0) usleep(delay);

    // Restart policy check
    if (s.config->process.lifecycle.restart_policy == "on-failure") {
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            start_service(name);
        } else if (WIFSIGNALED(status)) {
            start_service(name);
        }
    } else if (s.config->process.lifecycle.restart_policy == "always") {
        start_service(name);
    }
}

bool GServiceManager::is_managed_process(pid_t pid) const {
    return pid_to_name.find(pid) != pid_to_name.end();
}

void GServiceManager::print_status() {
    std::cout << get_status_str();
}

std::string GServiceManager::get_status_str() {
    std::stringstream ss;
    ss << "Ginit Service Status:" << std::endl;
    ss << "---------------------------------------------------" << std::endl;
    if (services.empty()) {
        ss << "No services loaded." << std::endl;
    }
    for (const auto& pair : services) {
        const auto& s = pair.second;
        ss << (s.running ? "[ RUNNING ] " : "[ STOPPED ] ") 
                  << pair.first << " (PID: " << (s.running ? std::to_string(s.pid) : "-") << ")" << std::endl;
        ss << "   Description: " << s.config->meta.description << std::endl;
    }
    return ss.str();
}

void GServiceManager::print_service_status(const std::string& name) {
    if (services.find(name) == services.end()) {
        std::cout << "Service " << name << " not found." << std::endl;
        return;
    }
    auto& s = services[name];
    std::cout << "Service: " << name << std::endl;
    std::cout << "  Status: " << (s.running ? "Running" : "Stopped") << std::endl;
    if (s.running) std::cout << "  PID: " << s.pid << std::endl;
    std::cout << "  Enabled: " << (s.enabled ? "Yes" : "No") << std::endl;
    std::cout << "  Description: " << s.config->meta.description << std::endl;
}

void GServiceManager::run_ipc_server() {
    std::thread([this]() {
        int server_fd, client_fd;
        struct sockaddr_un addr;

        if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
            perror("socket error");
            return;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, get_socket_path().c_str(), sizeof(addr.sun_path) - 1);

        unlink(get_socket_path().c_str());

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
            perror("bind error");
            return;
        }

        if (listen(server_fd, 5) == -1) {
            perror("listen error");
            return;
        }

        chmod(get_socket_path().c_str(), 0666);

        while (true) {
            if ((client_fd = accept(server_fd, NULL, NULL)) == -1) {
                perror("accept error");
                continue;
            }
            handle_ipc_client(client_fd);
        }
    }).detach();
}

void GServiceManager::handle_ipc_client(int client_fd) {
    char buf[1024];
    int n = read(client_fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        std::string cmd(buf);
        std::stringstream ss(cmd);
        std::string action, name;
        ss >> action >> name;

        std::string response;
        if (action == "status") {
            if (name.empty()) response = get_status_str();
            else {
                 if (services.find(name) != services.end()) {
                    auto& s = services[name];
                    std::stringstream status_ss;
                    status_ss << "Service: " << name << "\n";
                    status_ss << "  Status: " << (s.running ? "Running" : "Stopped") << "\n";
                    if (s.running) status_ss << "  PID: " << s.pid << "\n";
                    status_ss << "  Enabled: " << (s.enabled ? "Yes" : "No") << "\n";
                    status_ss << "  Description: " << s.config->meta.description << "\n";
                    response = status_ss.str();
                } else {
                    response = "Service '" + name + "' not found.\n";
                }
            }
        } else if (action == "start") {
            response = start_service(name);
        } else if (action == "stop") {
            response = stop_service(name);
        } else if (action == "restart") {
            response = restart_service(name);
        } else if (action == "enable") {
            response = enable_service(name);
        } else if (action == "disable") {
            response = disable_service(name);
        } else {
            response = "Unknown command\n";
        }
        write(client_fd, response.c_str(), response.size());
    }
    close(client_fd);
}

void GServiceManager::send_command(const std::string& command) {
    int fd;
    struct sockaddr_un addr;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, get_socket_path().c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        std::cerr << "Could not connect to ginit. Is it running as PID 1?" << std::endl;
        close(fd);
        return;
    }

    write(fd, command.c_str(), command.size());

    char buf[4096];
    int n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        std::cout << buf;
    }

    close(fd);
}

} // namespace ginit