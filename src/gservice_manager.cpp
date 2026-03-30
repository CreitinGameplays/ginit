#include "gservice_manager.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <sstream>
#include <string_view>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ginit {

namespace {

constexpr useconds_t kStopPollIntervalUs = 50000;

bool kernel_cmdline_has_token(std::string_view token) {
    std::ifstream cmdline("/proc/cmdline");
    if (!cmdline.is_open()) {
        return false;
    }

    std::string content;
    std::getline(cmdline, content);
    std::istringstream input(content);
    std::string current;
    while (input >> current) {
        if (current == token) {
            return true;
        }
    }
    return false;
}

bool info_console_logging_enabled() {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    if (getpid() != 1) {
        cached = 1;
        return true;
    }

    if (kernel_cmdline_has_token("geminios.verbose_boot=1")) {
        cached = 1;
        return true;
    }
    if (kernel_cmdline_has_token("geminios.verbose_boot=0")) {
        cached = 0;
        return false;
    }

    cached = kernel_cmdline_has_token("quiet") ? 0 : 1;
    return cached != 0;
}

void log_with_stream(FILE* stream, const char* level, const std::string& msg) {
    std::time_t now = std::time(nullptr);
    struct tm tm_now {};
    localtime_r(&now, &tm_now);

    char timestamp[16] = {};
    std::strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &tm_now);
    if (level) {
        std::fprintf(stream, "[%s] [%s] %s\n", timestamp, level, msg.c_str());
    } else {
        std::fprintf(stream, "[%s] %s\n", timestamp, msg.c_str());
    }
    std::fflush(stream);
}

void log_message(const std::string& msg) {
    if (info_console_logging_enabled()) {
        log_with_stream(stdout, nullptr, msg);
    }
}

void log_error(const std::string& msg) {
    log_with_stream(stderr, "ERR", msg);
}

std::string trim_copy(std::string value) {
    size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string join_strings(const std::vector<std::string>& values) {
    std::string out;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            out += ", ";
        }
        out += values[index];
    }
    return out;
}

bool string_starts_with(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

std::string wait_status_to_string(int status) {
    if (WIFEXITED(status)) {
        return "exit " + std::to_string(WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
        return "signal " + std::to_string(WTERMSIG(status));
    }
    if (WIFSTOPPED(status)) {
        return "stopped by signal " + std::to_string(WSTOPSIG(status));
    }
    return "status " + std::to_string(status);
}

bool ensure_directory(const char* path, mode_t mode) {
    if (mkdir(path, mode) == 0 || errno == EEXIST) {
        return true;
    }
    log_error(std::string("mkdir failed for ") + path + ": " + std::strerror(errno));
    return false;
}

bool set_close_on_exec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        return false;
    }
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

int open_log_fd(const std::string& log_file) {
    int fd = open(log_file.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
        log_error("Unable to open log file " + log_file + ": " + std::strerror(errno));
    }
    return fd;
}

std::string join_path(const char* base, const std::string& name) {
    return std::string(base) + "/" + name + ".gservice";
}

std::vector<std::string> socket_path_candidates() {
    std::vector<std::string> paths;
    const char* env_path = getenv("GINIT_SOCK");
    if (env_path && *env_path) {
        paths.emplace_back(env_path);
    }

    for (const char* candidate : {"/run/ginit.sock", "/dev/ginit.sock", "/tmp/ginit.sock"}) {
        if (std::find(paths.begin(), paths.end(), candidate) == paths.end()) {
            paths.emplace_back(candidate);
        }
    }
    return paths;
}

std::string parent_dir(std::string path) {
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) {
        return ".";
    }
    if (slash == 0) {
        return "/";
    }
    return path.substr(0, slash);
}

bool ensure_directory_tree(const std::string& path, mode_t mode) {
    if (path.empty() || path == ".") {
        return true;
    }

    size_t offset = 0;
    if (path[0] == '/') {
        offset = 1;
    }

    while (offset <= path.size()) {
        const size_t slash = path.find('/', offset);
        const std::string segment = slash == std::string::npos ? path : path.substr(0, slash);
        offset = slash == std::string::npos ? path.size() + 1 : slash + 1;

        if (segment.empty()) {
            continue;
        }
        if (mkdir(segment.c_str(), mode) != 0 && errno != EEXIST) {
            log_error("mkdir failed for " + segment + ": " + std::strerror(errno));
            return false;
        }
    }
    return true;
}

std::string socket_paths_for_display() {
    return join_strings(socket_path_candidates());
}

bool is_socket_node(const std::string& path) {
    struct stat st {};
    return lstat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode);
}

} // namespace

GServiceManager::GServiceManager() = default;

GServiceManager::~GServiceManager() {
    shutdown_ipc_server();
}

bool GServiceManager::is_enabled(const ServiceState& service) {
    return service.persistent_enabled || service.preset_enabled;
}

ServiceState* GServiceManager::find_service(const std::string& name) {
    for (auto& service : services_) {
        if (service.config.name == name) {
            return &service;
        }
    }
    return nullptr;
}

const ServiceState* GServiceManager::find_service(const std::string& name) const {
    for (const auto& service : services_) {
        if (service.config.name == name) {
            return &service;
        }
    }
    return nullptr;
}

ServiceState* GServiceManager::find_service_by_pid(pid_t pid) {
    for (auto& service : services_) {
        if (service.pid == pid) {
            return &service;
        }
    }
    return nullptr;
}

std::string GServiceManager::service_log_path(const std::string& service_name) const {
    return std::string("/var/log/ginit/") + service_name + ".log";
}

bool GServiceManager::load_service_file(const std::string& path, bool persistent_enabled, ServiceState** out_state) {
    std::string error;
    std::optional<GService> config = GServiceParser::parse_file(path, &error);
    if (!config) {
        log_error("[GSERVICE] Failed to parse " + path + ": " + error);
        return false;
    }

    ServiceState* existing = find_service(config->name);
    if (existing) {
        const bool was_running = existing->running;
        const pid_t previous_pid = existing->pid;
        const bool was_finished = existing->finished_successfully;
        const bool was_stopping = existing->stopping;
        const bool was_starting = existing->starting;
        const int restart_count = existing->restart_count;
        const std::string last_result = existing->last_result;
        const bool preset_enabled = existing->preset_enabled;
        existing->config = std::move(*config);
        existing->source_path = path;
        existing->persistent_enabled = existing->persistent_enabled || persistent_enabled;
        existing->preset_enabled = preset_enabled;
        existing->running = was_running;
        existing->pid = previous_pid;
        existing->finished_successfully = was_finished;
        existing->stopping = was_stopping;
        existing->starting = was_starting;
        existing->restart_count = restart_count;
        existing->last_result = last_result;
        if (out_state) {
            *out_state = existing;
        }
        log_message("[GSERVICE] Reloaded " + existing->config.name + " from " + path);
        return true;
    }

    ServiceState state;
    state.config = std::move(*config);
    state.source_path = path;
    state.persistent_enabled = persistent_enabled;
    services_.push_back(std::move(state));
    if (out_state) {
        *out_state = &services_.back();
    }

    log_message("[GSERVICE] Loaded " + services_.back().config.name + " from " + path);
    return true;
}

ServiceState* GServiceManager::load_service_by_name(const std::string& name, bool persistent_enabled) {
    if (ServiceState* existing = find_service(name)) {
        existing->persistent_enabled = existing->persistent_enabled || persistent_enabled;
        return existing;
    }

    ServiceState* state = nullptr;
    const std::string system_path = join_path(SYSTEM_SERVICES_DIR, name);
    if (access(system_path.c_str(), F_OK) == 0 && load_service_file(system_path, true, &state)) {
        return state;
    }

    const std::string available_path = join_path(AVAILABLE_SERVICES_DIR, name);
    if (access(available_path.c_str(), F_OK) == 0 && load_service_file(available_path, persistent_enabled, &state)) {
        return state;
    }

    return nullptr;
}

bool GServiceManager::load_service_snapshot(const std::string& name, ServiceState& out_state, std::string* error) const {
    out_state = {};

    const std::string system_path = join_path(SYSTEM_SERVICES_DIR, name);
    std::optional<GService> parsed = GServiceParser::parse_file(system_path, error);
    if (parsed) {
        out_state.config = std::move(*parsed);
        out_state.source_path = system_path;
        out_state.persistent_enabled = true;
        return true;
    }

    const std::string available_path = join_path(AVAILABLE_SERVICES_DIR, name);
    parsed = GServiceParser::parse_file(available_path, error);
    if (parsed) {
        out_state.config = std::move(*parsed);
        out_state.source_path = available_path;
        return true;
    }

    return false;
}

void GServiceManager::load_services_from_dir(const std::string& dir, bool enabled) {
    DIR* directory = opendir(dir.c_str());
    if (!directory) {
        if (errno != ENOENT) {
            log_error("[GSERVICE] Unable to open " + dir + ": " + std::strerror(errno));
        }
        return;
    }

    std::vector<std::string> filenames;
    struct dirent* entry = nullptr;
    while ((entry = readdir(directory)) != nullptr) {
        const std::string filename = entry->d_name;
        if (string_starts_with(filename, ".")) {
            continue;
        }
        if (filename.size() > 9 && filename.substr(filename.size() - 9) == ".gservice") {
            filenames.push_back(filename);
        }
    }
    closedir(directory);

    std::sort(filenames.begin(), filenames.end());
    for (const auto& filename : filenames) {
        load_service_file(dir + "/" + filename, enabled, nullptr);
    }
}

bool GServiceManager::apply_environment(const GService& config, std::string* error) {
    for (const auto& variable : config.env_vars) {
        if (setenv(variable.name.c_str(), variable.value.c_str(), 1) != 0) {
            if (error) {
                *error = "setenv failed for " + variable.name + ": " + std::strerror(errno);
            }
            return false;
        }
    }

    if (!config.env_file.empty()) {
        std::ifstream file(config.env_file);
        if (!file.is_open()) {
            if (error) {
                *error = "unable to open env file " + config.env_file + ": " + std::strerror(errno);
            }
            return false;
        }

        std::string line;
        size_t line_number = 0;
        while (std::getline(file, line)) {
            ++line_number;
            line = trim_copy(std::move(line));
            if (line.empty() || line[0] == '#') {
                continue;
            }
            const size_t separator = line.find('=');
            if (separator == std::string::npos || separator == 0) {
                if (error) {
                    *error = "invalid env entry in " + config.env_file + " on line " + std::to_string(line_number);
                }
                return false;
            }

            std::string name = trim_copy(line.substr(0, separator));
            std::string value = trim_copy(line.substr(separator + 1));
            if (name.empty()) {
                if (error) {
                    *error = "invalid env entry in " + config.env_file + " on line " + std::to_string(line_number);
                }
                return false;
            }
            if (setenv(name.c_str(), value.c_str(), 1) != 0) {
                if (error) {
                    *error = "setenv failed for " + name + ": " + std::strerror(errno);
                }
                return false;
            }
        }
    }

    if (!config.work_dir.empty() && chdir(config.work_dir.c_str()) != 0) {
        if (error) {
            *error = "chdir(" + config.work_dir + ") failed: " + std::strerror(errno);
        }
        return false;
    }

    return true;
}

bool GServiceManager::apply_security(const GService& config, std::string* error) {
    gid_t target_gid = static_cast<gid_t>(-1);
    uid_t target_uid = static_cast<uid_t>(-1);
    const char* target_user_name = nullptr;

    if (!config.user.empty()) {
        struct passwd* pwd = getpwnam(config.user.c_str());
        if (!pwd) {
            if (error) {
                *error = "user '" + config.user + "' not found";
            }
            return false;
        }
        target_uid = pwd->pw_uid;
        target_gid = pwd->pw_gid;
        target_user_name = pwd->pw_name;
    }

    if (!config.group.empty()) {
        struct group* grp = getgrnam(config.group.c_str());
        if (!grp) {
            if (error) {
                *error = "group '" + config.group + "' not found";
            }
            return false;
        }
        target_gid = grp->gr_gid;
    }

    if (target_user_name) {
        if (initgroups(target_user_name, target_gid != static_cast<gid_t>(-1) ? target_gid : 0) != 0) {
            if (error) {
                *error = "initgroups failed for user '" + config.user + "': " + std::strerror(errno);
            }
            return false;
        }
    }

    if (target_gid != static_cast<gid_t>(-1) && setgid(target_gid) != 0) {
        if (error) {
            *error = std::string("setgid failed: ") + std::strerror(errno);
        }
        return false;
    }

    if (target_uid != static_cast<uid_t>(-1) && setuid(target_uid) != 0) {
        if (error) {
            *error = std::string("setuid failed: ") + std::strerror(errno);
        }
        return false;
    }

    if (config.no_new_privileges && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        if (error) {
            *error = std::string("prctl(PR_SET_NO_NEW_PRIVS) failed: ") + std::strerror(errno);
        }
        return false;
    }

    return true;
}

int GServiceManager::run_shell_command(const GService& config, const std::string& command, const std::string& log_file) {
    pid_t pid = fork();
    if (pid < 0) {
        log_error("[GSERVICE] fork failed for " + config.name + ": " + std::strerror(errno));
        return -1;
    }

    if (pid == 0) {
        int log_fd = open_log_fd(log_file);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }

        std::string error;
        if (!apply_environment(config, &error) || !apply_security(config, &error)) {
            std::fprintf(stderr, "[GSERVICE] %s\n", error.c_str());
            _exit(126);
        }

        execl("/bin/sh", "sh", "-c", command.c_str(), nullptr);
        std::fprintf(stderr, "[GSERVICE] exec /bin/sh failed for %s: %s\n", config.name.c_str(), std::strerror(errno));
        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            log_error("[GSERVICE] waitpid failed for " + config.name + ": " + std::strerror(errno));
            return -1;
        }
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return -1;
}

pid_t GServiceManager::spawn_process(const GService& config) {
    ensure_directory("/var/log", 0755);
    ensure_directory("/var/log/ginit", 0755);
    const std::string log_file = service_log_path(config.name);

    if (!config.start_pre.empty()) {
        log_message("[GSERVICE] Running start_pre for " + config.name);
        const int pre_status = run_shell_command(config, config.start_pre, log_file);
        if (pre_status != 0) {
            log_error("[GSERVICE] start_pre failed for " + config.name + " with " + std::to_string(pre_status));
            return -1;
        }
    }

    const pid_t pid = fork();
    if (pid < 0) {
        log_error("[GSERVICE] fork failed for " + config.name + ": " + std::strerror(errno));
        return -1;
    }

    if (pid == 0) {
        int log_fd = open_log_fd(log_file);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }

        std::string error;
        if (!apply_environment(config, &error) || !apply_security(config, &error)) {
            std::fprintf(stderr, "[GSERVICE] %s\n", error.c_str());
            _exit(126);
        }

        execl("/bin/sh", "sh", "-c", config.start.c_str(), nullptr);
        std::fprintf(stderr, "[GSERVICE] exec /bin/sh failed for %s: %s\n", config.name.c_str(), std::strerror(errno));
        _exit(127);
    }

    return pid;
}

std::vector<size_t> GServiceManager::get_service_order() const {
    std::vector<size_t> order;
    order.reserve(services_.size());
    std::vector<unsigned char> state(services_.size(), 0);
    for (size_t index = 0; index < services_.size(); ++index) {
        if (state[index] == 0) {
            visit(index, state, order);
        }
    }
    return order;
}

void GServiceManager::visit(size_t index, std::vector<unsigned char>& state, std::vector<size_t>& order) const {
    if (state[index] == 2) {
        return;
    }
    if (state[index] == 1) {
        log_error("[GSERVICE] Dependency cycle detected involving " + services_[index].config.name);
        return;
    }

    state[index] = 1;
    for (const auto& dep_name : services_[index].config.after) {
        for (size_t dep_index = 0; dep_index < services_.size(); ++dep_index) {
            if (services_[dep_index].config.name == dep_name) {
                visit(dep_index, state, order);
                break;
            }
        }
    }

    state[index] = 2;
    order.push_back(index);
}

void GServiceManager::start_enabled_services() {
    const std::vector<size_t> order = get_service_order();
    for (size_t index : order) {
        if (is_enabled(services_[index]) && !services_[index].running) {
            start_service(services_[index].config.name);
        }
    }
}

std::string GServiceManager::start_service(const std::string& name) {
    if (name.empty()) {
        return "Error: Missing service name.\n";
    }

    ServiceState* service = find_service(name);
    if (!service) {
        service = load_service_by_name(name, false);
    }
    if (!service) {
        return "Error: Service '" + name + "' not found.\n";
    }

    if (service->running) {
        return "Service '" + name + "' is already running (PID " + std::to_string(service->pid) + ").\n";
    }
    if (service->config.type == ServiceType::Oneshot && service->finished_successfully) {
        return "Oneshot service '" + name + "' has already finished successfully.\n";
    }
    if (service->starting) {
        return "Error: Dependency cycle detected while starting '" + name + "'.\n";
    }

    service->starting = true;
    for (const auto& dependency : service->config.required_services) {
        ServiceState* required = find_service(dependency);
        if (!required) {
            required = load_service_by_name(dependency, false);
        }
        if (!required) {
            service->starting = false;
            return "Failed to load requirement '" + dependency + "' for " + name + ".\n";
        }
        if (!required->running && !required->finished_successfully) {
            log_message("[GSERVICE] Starting requirement " + dependency + " for " + name);
            const std::string result = start_service(dependency);
            if (!required->running && !required->finished_successfully) {
                service->starting = false;
                return "Failed to start requirement '" + dependency + "' for " + name + ".\n" + result;
            }
        }
    }

    for (const auto& dependency : service->config.wants) {
        ServiceState* wanted = find_service(dependency);
        if (!wanted) {
            wanted = load_service_by_name(dependency, false);
        }
        if (wanted && !wanted->running && !wanted->finished_successfully) {
            log_message("[GSERVICE] Starting wanted dependency " + dependency + " for " + name);
            start_service(dependency);
        }
    }

    log_message("[GSERVICE] Starting " + name + "...");
    service->finished_successfully = false;
    service->stopping = false;
    service->last_result = "starting";
    service->pid = spawn_process(service->config);
    if (service->pid <= 0) {
        service->starting = false;
        service->pid = -1;
        service->last_result = "start failed";
        return "Failed to start " + name + ".\n";
    }

    if (service->config.type == ServiceType::Oneshot) {
        int status = 0;
        while (waitpid(service->pid, &status, 0) < 0) {
            if (errno != EINTR) {
                log_error("[GSERVICE] waitpid failed for oneshot " + name + ": " + std::strerror(errno));
                service->pid = -1;
                service->starting = false;
                service->last_result = "waitpid failed";
                return "Oneshot " + name + " failed.\n";
            }
        }

        service->pid = -1;
        service->running = false;
        service->starting = false;
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            service->finished_successfully = true;
            service->last_result = "exit 0";
            log_message("[GSERVICE] Oneshot " + name + " finished successfully.");
            return "Oneshot " + name + " finished successfully.\n";
        }

        service->finished_successfully = false;
        service->last_result = wait_status_to_string(status);
        log_error("[GSERVICE] Oneshot " + name + " failed with " + wait_status_to_string(status));
        return "Oneshot " + name + " failed.\n";
    }

    service->running = true;
    service->finished_successfully = false;
    service->starting = false;
    service->last_result = "running";
    return "Started " + name + " (PID " + std::to_string(service->pid) + ").\n";
}

bool GServiceManager::wait_for_service_exit(ServiceState& service, pid_t expected_pid, uint32_t timeout_ms, std::string* detail) {
    const uint32_t effective_timeout = timeout_ms == 0 ? 1 : timeout_ms;
    uint32_t elapsed_ms = 0;

    while (elapsed_ms <= effective_timeout) {
        int status = 0;
        pid_t result = waitpid(expected_pid, &status, WNOHANG);
        if (result == expected_pid) {
            handle_process_death(expected_pid, status);
            if (detail) {
                *detail = wait_status_to_string(status);
            }
            return true;
        }

        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECHILD) {
                service.running = false;
                service.pid = -1;
                service.stopping = false;
                if (detail) {
                    *detail = "process already reaped";
                }
                return true;
            }
            if (detail) {
                *detail = std::strerror(errno);
            }
            return false;
        }

        usleep(kStopPollIntervalUs);
        elapsed_ms += static_cast<uint32_t>(kStopPollIntervalUs / 1000);
    }

    if (detail) {
        *detail = "timeout";
    }
    return false;
}

std::string GServiceManager::stop_service(const std::string& name) {
    if (name.empty()) {
        return "Error: Missing service name.\n";
    }

    ServiceState* service = find_service(name);
    if (!service) {
        return "Error: Service '" + name + "' not found.\n";
    }
    if (!service->running || service->pid <= 0) {
        service->running = false;
        service->pid = -1;
        return "Service '" + name + "' is not running.\n";
    }

    const pid_t expected_pid = service->pid;
    service->stopping = true;
    service->last_result = "stopping";

    if (!service->config.stop.empty()) {
        log_message("[GSERVICE] Running stop command for " + name);
        const int rc = run_shell_command(service->config, service->config.stop, service_log_path(name));
        if (rc != 0) {
            log_error("[GSERVICE] stop command failed for " + name + " with " + std::to_string(rc));
        }
    }

    if (kill(expected_pid, SIGTERM) != 0 && errno != ESRCH) {
        service->stopping = false;
        service->last_result = std::string("stop failed: ") + std::strerror(errno);
        return "Failed to stop " + name + ": " + std::string(std::strerror(errno)) + ".\n";
    }

    std::string detail;
    if (wait_for_service_exit(*service, expected_pid, service->config.stop_timeout_ms, &detail)) {
        return "Stopped " + name + " (" + detail + ").\n";
    }

    log_error("[GSERVICE] " + name + " did not stop after SIGTERM; sending SIGKILL");
    if (kill(expected_pid, SIGKILL) != 0 && errno != ESRCH) {
        service->stopping = false;
        service->last_result = std::string("kill failed: ") + std::strerror(errno);
        return "Failed to kill " + name + ": " + std::string(std::strerror(errno)) + ".\n";
    }

    if (wait_for_service_exit(*service, expected_pid, 2000, &detail)) {
        return "Stopped " + name + " after SIGKILL (" + detail + ").\n";
    }

    service->stopping = false;
    service->last_result = "stop timeout";
    return "Timed out while stopping " + name + ".\n";
}

std::string GServiceManager::restart_service(const std::string& name) {
    if (name.empty()) {
        return "Error: Missing service name.\n";
    }

    ServiceState* service = find_service(name);
    if (!service) {
        return "Error: Service '" + name + "' not found.\n";
    }

    std::string out;
    if (service->running) {
        out = stop_service(name);
        if (service->running) {
            return out;
        }
    }
    return out + start_service(name);
}

std::string GServiceManager::enable_service(const std::string& name) {
    if (name.empty()) {
        return "Error: Missing service name.\n";
    }

    const std::string src = join_path(AVAILABLE_SERVICES_DIR, name);
    const std::string dest = join_path(SYSTEM_SERVICES_DIR, name);

    ensure_directory("/etc/ginit", 0755);
    ensure_directory("/etc/ginit/services", 0755);
    ensure_directory(SYSTEM_SERVICES_DIR, 0755);

    if (access(src.c_str(), F_OK) != 0) {
        return "Error: Service '" + name + "' not available to enable.\n";
    }

    if (symlink(src.c_str(), dest.c_str()) != 0) {
        if (errno != EEXIST) {
            return "Failed to enable " + name + ": " + std::string(std::strerror(errno)) + ".\n";
        }
    }

    if (ServiceState* service = find_service(name)) {
        service->persistent_enabled = true;
    }
    log_message("[GSERVICE] Enabled " + name);
    return "Enabled " + name + ".\n";
}

std::string GServiceManager::disable_service(const std::string& name) {
    if (name.empty()) {
        return "Error: Missing service name.\n";
    }

    const std::string dest = join_path(SYSTEM_SERVICES_DIR, name);
    if (unlink(dest.c_str()) != 0) {
        if (errno == ENOENT) {
            return "Service '" + name + "' is not enabled.\n";
        }
        return "Failed to disable " + name + ": " + std::string(std::strerror(errno)) + ".\n";
    }

    if (ServiceState* service = find_service(name)) {
        service->persistent_enabled = false;
    }
    log_message("[GSERVICE] Disabled " + name);
    if (ServiceState* service = find_service(name); service && service->preset_enabled) {
        return "Disabled persistent enablement for " + name + ", but it is still started by a boot preset.\n";
    }
    return "Disabled " + name + ".\n";
}

std::string GServiceManager::preset_service(const std::string& name) {
    if (name.empty()) {
        return "Error: Missing service name.\n";
    }

    ServiceState* service = load_service_by_name(name, false);
    if (!service) {
        return "Error: Service '" + name + "' not found for boot preset.\n";
    }

    service->preset_enabled = true;
    return "Preset " + name + ".\n";
}

void GServiceManager::handle_process_death(pid_t pid, int status) {
    ServiceState* service = find_service_by_pid(pid);
    if (!service) {
        return;
    }

    const std::string name = service->config.name;
    service->running = false;
    service->pid = -1;
    service->starting = false;
    service->last_result = wait_status_to_string(status);

    log_message("[GSERVICE] Service " + name + " (" + std::to_string(pid) + ") exited with " + wait_status_to_string(status));

    if (service->config.type == ServiceType::Oneshot) {
        service->finished_successfully = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        service->stopping = false;
        return;
    }

    if (service->stopping) {
        service->stopping = false;
        service->finished_successfully = false;
        return;
    }

    if (service->config.restart_delay_us > 0) {
        usleep(service->config.restart_delay_us);
    }

    bool should_restart = false;
    if (service->config.restart_policy == RestartPolicy::Always) {
        should_restart = true;
    } else if (service->config.restart_policy == RestartPolicy::OnFailure) {
        should_restart = !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }

    if (should_restart) {
        ++service->restart_count;
        log_message("[GSERVICE] Restarting " + name);
        start_service(name);
    }
}

bool GServiceManager::is_managed_process(pid_t pid) const {
    for (const auto& service : services_) {
        if (service.pid == pid) {
            return true;
        }
    }
    return false;
}

std::string GServiceManager::status_for_service(const ServiceState& service) const {
    std::string out;
    out.reserve(240);
    out += "Service: " + service.config.name + "\n";
    out += "  Status: ";
    out += service.running ? "Running" : (service.finished_successfully ? "Finished" : "Stopped");
    out += "\n";
    if (service.running) {
        out += "  PID: " + std::to_string(service.pid) + "\n";
    }
    out += "  Enabled: ";
    out += is_enabled(service) ? "Yes\n" : "No\n";
    out += "  Persistent: ";
    out += service.persistent_enabled ? "Yes\n" : "No\n";
    out += "  Boot preset: ";
    out += service.preset_enabled ? "Yes\n" : "No\n";
    out += "  Description: " + service.config.description + "\n";
    return out;
}

std::string GServiceManager::detail_for_service(const ServiceState& service) const {
    std::string out = status_for_service(service);
    if (!service.source_path.empty()) {
        out += "  Source: " + service.source_path + "\n";
    }
    out += "  Type: ";
    out += service.config.type == ServiceType::Oneshot ? "oneshot\n" : "simple\n";
    out += "  Restart policy: ";
    if (service.config.restart_policy == RestartPolicy::Always) {
        out += "always\n";
    } else if (service.config.restart_policy == RestartPolicy::OnFailure) {
        out += "on-failure\n";
    } else {
        out += "never\n";
    }
    if (service.config.restart_delay_us > 0) {
        out += "  Restart delay: " + std::to_string(service.config.restart_delay_us / 1000U) + " ms\n";
    }
    out += "  Stop timeout: " + std::to_string(service.config.stop_timeout_ms) + " ms\n";
    if (!service.config.user.empty()) {
        out += "  User: " + service.config.user + "\n";
    }
    if (!service.config.group.empty()) {
        out += "  Group: " + service.config.group + "\n";
    }
    if (!service.config.work_dir.empty()) {
        out += "  Work dir: " + service.config.work_dir + "\n";
    }
    if (!service.config.env_file.empty()) {
        out += "  Env file: " + service.config.env_file + "\n";
    }
    if (!service.config.after.empty()) {
        out += "  After: " + join_strings(service.config.after) + "\n";
    }
    if (!service.config.required_services.empty()) {
        out += "  Requires: " + join_strings(service.config.required_services) + "\n";
    }
    if (!service.config.wants.empty()) {
        out += "  Wants: " + join_strings(service.config.wants) + "\n";
    }
    out += "  Log file: " + service_log_path(service.config.name) + "\n";
    if (!service.config.start_pre.empty()) {
        out += "  StartPre: " + service.config.start_pre + "\n";
    }
    out += "  Start: " + service.config.start + "\n";
    if (!service.config.stop.empty()) {
        out += "  Stop: " + service.config.stop + "\n";
    }
    if (!service.last_result.empty()) {
        out += "  Last result: " + service.last_result + "\n";
    }
    if (service.restart_count > 0) {
        out += "  Restart count: " + std::to_string(service.restart_count) + "\n";
    }
    return out;
}

void GServiceManager::print_status() {
    log_message(get_status_str());
}

std::string GServiceManager::get_status_str() const {
    std::string out;
    out.reserve(128 + services_.size() * 96);
    out += "Ginit Service Status:\n";
    out += "---------------------------------------------------\n";
    if (services_.empty()) {
        out += "No services loaded.\n";
        return out;
    }

    for (const auto& service : services_) {
        if (service.running) {
            out += "[ RUNNING ] ";
        } else if (service.finished_successfully) {
            out += "[ FINISHED ] ";
        } else {
            out += "[ STOPPED ] ";
        }
        out += service.config.name;
        out += " (PID: ";
        out += service.running ? std::to_string(service.pid) : "-";
        out += ")\n";
        if (service.persistent_enabled) {
            out += "   Boot: persistent";
            if (service.preset_enabled) out += ", preset";
            out += "\n";
        } else if (service.preset_enabled) {
            out += "   Boot: preset\n";
        }
        out += "   Description: " + service.config.description + "\n";
    }
    return out;
}

void GServiceManager::print_service_status(const std::string& name) {
    const ServiceState* service = find_service(name);
    if (!service) {
        log_message("Service " + name + " not found.");
        return;
    }
    log_message(status_for_service(*service));
}

std::string GServiceManager::get_service_details_str(const std::string& name) const {
    if (name.empty()) {
        return "Error: Missing service name.\n";
    }

    if (const ServiceState* service = find_service(name)) {
        return detail_for_service(*service);
    }

    std::string error;
    ServiceState unloaded;
    if (load_service_snapshot(name, unloaded, &error)) {
        return detail_for_service(unloaded);
    }

    return "Service '" + name + "' not found.\n";
}

bool GServiceManager::start_ipc_server() {
    if (ipc_server_fd_ >= 0) {
        return true;
    }

    for (const std::string& candidate : socket_path_candidates()) {
        struct sockaddr_un addr {};
        if (candidate.size() >= sizeof(addr.sun_path)) {
            log_error("[GSERVICE] IPC socket path is too long: " + candidate);
            continue;
        }
        if (!ensure_directory_tree(parent_dir(candidate), 0755)) {
            log_error("[GSERVICE] IPC socket directory is unavailable for " + candidate);
            continue;
        }

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            log_error("[GSERVICE] socket error while opening " + candidate + ": " + std::string(std::strerror(errno)));
            continue;
        }
        if (!set_close_on_exec(fd)) {
            log_error("[GSERVICE] failed to mark IPC socket close-on-exec");
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            log_error("[GSERVICE] failed to mark IPC socket nonblocking");
            close(fd);
            continue;
        }

        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", candidate.c_str());

        unlink(candidate.c_str());
        if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            log_error("[GSERVICE] bind error on " + candidate + ": " + std::string(std::strerror(errno)));
            close(fd);
            continue;
        }
        if (listen(fd, 8) != 0) {
            log_error("[GSERVICE] listen error on " + candidate + ": " + std::string(std::strerror(errno)));
            close(fd);
            unlink(candidate.c_str());
            continue;
        }
        if (chmod(candidate.c_str(), 0666) != 0) {
            log_error("[GSERVICE] chmod on IPC socket failed for " + candidate + ": " + std::string(std::strerror(errno)));
        }

        socket_path_ = candidate;
        ipc_server_fd_ = fd;
        log_message("[GSERVICE] IPC control socket ready at " + socket_path_);
        return true;
    }

    log_error("[GSERVICE] failed to start IPC server on any control socket path: " + socket_paths_for_display());
    return false;
}

void GServiceManager::shutdown_ipc_server() {
    if (ipc_server_fd_ >= 0) {
        close(ipc_server_fd_);
        ipc_server_fd_ = -1;
    }
    if (!socket_path_.empty()) {
        unlink(socket_path_.c_str());
    }
}

int GServiceManager::ipc_server_fd() const {
    return ipc_server_fd_;
}

bool GServiceManager::write_all(int fd, const char* data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return true;
}

std::string GServiceManager::handle_command(const std::string& command) {
    const std::string trimmed = trim_copy(command);
    if (trimmed.empty()) {
        return "Empty command\n";
    }

    const size_t space = trimmed.find_first_of(" \t\r\n");
    const std::string action = space == std::string::npos ? trimmed : trimmed.substr(0, space);
    std::string name;
    if (space != std::string::npos) {
        name = trim_copy(trimmed.substr(space + 1));
    }

    if (action == "status") {
        if (name.empty()) {
            return get_status_str();
        }

        if (ServiceState* service = find_service(name)) {
            return status_for_service(*service);
        }

        std::string error;
        ServiceState unloaded;
        if (load_service_snapshot(name, unloaded, &error)) {
            return status_for_service(unloaded);
        }

        return "Service '" + name + "' not found.\n";
    }
    if (action == "show") {
        if (name.empty()) {
            return "Error: Missing service name.\n";
        }

        return get_service_details_str(name);
    }
    if (action == "start") {
        return start_service(name);
    }
    if (action == "stop") {
        return stop_service(name);
    }
    if (action == "restart") {
        return restart_service(name);
    }
    if (action == "enable") {
        return enable_service(name);
    }
    if (action == "disable") {
        return disable_service(name);
    }
    return "Unknown command\n";
}

void GServiceManager::handle_ipc_client(int client_fd) {
    char buffer[1024];
    ssize_t received = 0;
    while (true) {
        received = read(client_fd, buffer, sizeof(buffer) - 1);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    if (received > 0) {
        buffer[received] = '\0';
        const std::string response = handle_command(buffer);
        if (!write_all(client_fd, response.c_str(), response.size())) {
            log_error("[GSERVICE] failed to write IPC response");
        }
    }
}

void GServiceManager::accept_pending_ipc_clients() {
    if (ipc_server_fd_ < 0) {
        return;
    }

    while (true) {
        int client_fd = accept(ipc_server_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            log_error("[GSERVICE] accept error: " + std::string(std::strerror(errno)));
            break;
        }

        if (!set_close_on_exec(client_fd)) {
            log_error("[GSERVICE] failed to mark IPC client close-on-exec");
        }
        handle_ipc_client(client_fd);
        close(client_fd);
    }
}

bool GServiceManager::send_command(const std::string& command, std::string* response, std::string* error) {
    std::string first_error;
    bool saw_socket_node = false;
    bool saw_unreachable_socket = false;

    for (const std::string& socket_path : socket_path_candidates()) {
        if (is_socket_node(socket_path)) {
            saw_socket_node = true;
        }

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            if (first_error.empty()) {
                first_error = std::string("socket error: ") + std::strerror(errno);
            }
            continue;
        }
        set_close_on_exec(fd);

        struct sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        if (socket_path.size() >= sizeof(addr.sun_path)) {
            if (first_error.empty()) {
                first_error = "ginit socket path is too long: " + socket_path;
            }
            close(fd);
            continue;
        }
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path.c_str());

        if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            const int connect_errno = errno;
            if (connect_errno == ECONNREFUSED || connect_errno == ENOENT || connect_errno == ECONNRESET) {
                saw_unreachable_socket = true;
            }
            if (first_error.empty()) {
                first_error = "Could not connect to ginit via " + socket_path + ": " + std::strerror(connect_errno);
            }
            close(fd);
            continue;
        }

        if (!write_all(fd, command.c_str(), command.size())) {
            if (error) {
                *error = "Failed to send command to ginit via " + socket_path;
            }
            close(fd);
            return false;
        }

        char buffer[4096];
        while (true) {
            ssize_t received = read(fd, buffer, sizeof(buffer) - 1);
            if (received < 0 && errno == EINTR) {
                continue;
            }
            if (received <= 0) {
                break;
            }
            buffer[received] = '\0';
            if (response) {
                response->append(buffer, static_cast<size_t>(received));
            } else {
                std::fputs(buffer, stdout);
            }
        }

        close(fd);
        return true;
    }

    if (error) {
        if (!saw_socket_node) {
            *error = "Could not connect to ginit. No control socket was found in: " + socket_paths_for_display();
        } else if (saw_unreachable_socket) {
            *error = "Could not connect to ginit. Its control socket exists but is not accepting commands.";
        } else if (!first_error.empty()) {
            *error = first_error;
        } else {
            *error = "Could not connect to ginit. Is it running as PID 1?";
        }
    }
    return false;
}

bool GServiceManager::control_socket_present(std::string* path) {
    for (const std::string& candidate : socket_path_candidates()) {
        if (is_socket_node(candidate)) {
            if (path) {
                *path = candidate;
            }
            return true;
        }
    }
    return false;
}

} // namespace ginit
