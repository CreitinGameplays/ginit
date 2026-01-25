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
#include <ctime>
#include <iomanip>
#include <pwd.h>
#include <grp.h>
#include <sys/prctl.h>

namespace ginit {

void log_message(const std::string& msg) {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::cout << "[" << std::put_time(&tm, "%H:%M:%S") << "] " << msg << std::endl;
}

void log_error(const std::string& msg) {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::cerr << "[" << std::put_time(&tm, "%H:%M:%S") << "] [ERR] " << msg << std::endl;
}

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
                log_message("[GSERVICE] Loaded " + name + " from " + filename);
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
             log_error("[GSERVICE] User " + config.process.user + " not found!");
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
        log_message("[GSERVICE] Running start_pre for " + config.name);
        
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
                 log_error("[GSERVICE] start_pre failed for " + config.name);
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

std::string GServiceManager::stop_service(const std::string& name) {
    if (services.find(name) == services.end()) return "Error: Service '" + name + "' not found.\n";
    auto& s = services[name];
    if (!s.running) return "Service '" + name + "' is not running.\n";

    log_message("[GSERVICE] Stopping " + name + " (PID " + std::to_string(s.pid) + ")...");
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
        log_message("[GSERVICE] Enabled " + name);
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
        log_message("[GSERVICE] Disabled " + name);
        if (services.count(name)) services[name].enabled = false;
        return "Disabled " + name + ".\n";
    }
}

std::vector<std::string> GServiceManager::get_service_order() {
    std::map<std::string, bool> visited;
    std::map<std::string, bool> stack;
    std::vector<std::string> order;

    for (const auto& pair : services) {
        if (!visited[pair.first]) {
            visit(pair.first, visited, stack, order);
        }
    }

    return order;
}

void GServiceManager::visit(const std::string& name, std::map<std::string, bool>& visited, std::map<std::string, bool>& stack, std::vector<std::string>& order) {
    visited[name] = true;
    stack[name] = true;

    if (services.count(name)) {
        for (const auto& dep : services[name].config->meta.deps.after) {
            if (services.count(dep)) {
                if (!visited[dep]) {
                    visit(dep, visited, stack, order);
                }
            }
        }
    }

    stack[name] = false;
    order.push_back(name);
}

void GServiceManager::start_enabled_services() {
    std::vector<std::string> order = get_service_order();
    for (const auto& name : order) {
        if (services[name].enabled && !services[name].running) {
            start_service(name);
        }
    }
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
    if (s.finished_successfully && s.config->process.type == "oneshot") return "Oneshot service '" + name + "' has already finished successfully.\n";

    // Handle 'Requires' dependencies
    for (const auto& req : s.config->meta.deps.requires) {
        if (services.find(req) == services.end() || (!services[req].running && !services[req].finished_successfully)) {
            log_message("[GSERVICE] Starting requirement " + req + " for " + name);
            start_service(req);
            if (!services[req].running && !services[req].finished_successfully) {
                 return "Failed to start requirement " + req + " for " + name + ".\n";
            }
        }
    }

    log_message("[GSERVICE] Starting " + name + "...");
    s.pid = spawn_process(*(s.config));
    if (s.pid > 0) {
        if (s.config->process.type == "oneshot") {
            int status;
            waitpid(s.pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                log_message("[GSERVICE] Oneshot " + name + " finished successfully.");
                s.running = false; 
                s.finished_successfully = true;
                return "Oneshot " + name + " finished successfully.\n";
            } else {
                log_error("[GSERVICE] Oneshot " + name + " failed.");
                s.finished_successfully = false;
                return "Oneshot " + name + " failed.\n";
            }
        } else {
            s.running = true;
            s.finished_successfully = false; // Reset if it was a re-start
            pid_to_name[s.pid] = name;
            return "Started " + name + " (PID " + std::to_string(s.pid) + ").\n";
        }
    }
    return "Failed to start " + name + ".\n";
}

void GServiceManager::handle_process_death(pid_t pid, int status) {
    if (pid_to_name.find(pid) == pid_to_name.end()) return;

    std::string name = pid_to_name[pid];
    auto& s = services[name];
    s.running = false;
    pid_to_name.erase(pid);

    log_message("[GSERVICE] Service " + name + " (pid " + std::to_string(pid) + ") exited with status " + std::to_string(status));

    // Do not supervise/restart oneshot services here, they are handled in start_service
    if (s.config->process.type == "oneshot") return;

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
    log_message(get_status_str());
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
        std::string status_label = "[ STOPPED ] ";
        if (s.running) status_label = "[ RUNNING ] ";
        else if (s.finished_successfully) status_label = "[ FINISHED ] ";

        ss << status_label 
                  << pair.first << " (PID: " << (s.running ? std::to_string(s.pid) : "-") << ")" << std::endl;
        ss << "   Description: " << s.config->meta.description << std::endl;
    }
    return ss.str();
}

void GServiceManager::print_service_status(const std::string& name) {
    if (services.find(name) == services.end()) {
        log_message("Service " + name + " not found.");
        return;
    }
    auto& s = services[name];
    std::stringstream ss;
    ss << "Service: " << name << "\n";
    std::string status_str = s.running ? "Running" : (s.finished_successfully ? "Finished" : "Stopped");
    ss << "  Status: " << status_str << "\n";
    if (s.running) ss << "  PID: " << s.pid << "\n";
    ss << "  Enabled: " << (s.enabled ? "Yes" : "No") << "\n";
    ss << "  Description: " << s.config->meta.description << "\n";
    log_message(ss.str());
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
                    std::string status_str = s.running ? "Running" : (s.finished_successfully ? "Finished" : "Stopped");
                    status_ss << "  Status: " << status_str << "\n";
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