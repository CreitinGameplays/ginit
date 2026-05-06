#include <array>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <map>
#include <poll.h>
#include <set>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/reboot.h>
#include <dirent.h>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <cstdio>
#include <csignal>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <selinux/selinux.h>
#include "signals.h"
#include "sys_info.h"
#include "user_mgmt.h"
#include "gservice_manager.hpp"

ginit::GServiceManager service_manager;
volatile sig_atomic_t g_child_event = 0;

constexpr const char* AVAILABLE_SERVICES_DIR = "/usr/lib/ginit/services";
constexpr const char* SYSTEM_SERVICES_DIR = "/etc/ginit/services/system";
constexpr const char* VENDOR_BOOT_SERVICES_PATH = "/usr/lib/ginit/boot-services.conf";
constexpr const char* ADMIN_BOOT_SERVICES_PATH = "/etc/ginit/boot-services.conf";

void safe_mkdir(const char* dir);
std::string trim_copy_local(const std::string& value);

struct ConfigIssue {
    std::string severity;
    std::string message;
};

struct LocalServiceInfo {
    ginit::GService config;
    std::string source_path;
    bool persistent_enabled = false;
    bool preset_enabled = false;
};

bool string_starts_with_local(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

bool response_indicates_failure(const std::string& response) {
    return string_starts_with_local(response, "Error:") ||
           string_starts_with_local(response, "Failed") ||
           string_starts_with_local(response, "Unknown command") ||
           response.find(" not found.\n") != std::string::npos;
}

void add_issue(std::vector<ConfigIssue>& issues, const char* severity, const std::string& message) {
    issues.push_back({severity, message});
}

std::string join_strings_local(const std::vector<std::string>& values) {
    std::string out;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            out += ", ";
        }
        out += values[index];
    }
    return out;
}

bool has_gservice_suffix(const std::string& filename) {
    return filename.size() > 9 && filename.substr(filename.size() - 9) == ".gservice";
}

bool is_live_environment() {
    return access("/etc/geminios-live", F_OK) == 0;
}

std::string basename_copy_local(const char* path) {
    if (!path || !*path) {
        return "";
    }
    const char* slash = std::strrchr(path, '/');
    return slash ? std::string(slash + 1) : std::string(path);
}

bool is_valid_service_ref(const std::string& name) {
    if (name.empty()) {
        return false;
    }
    for (unsigned char ch : name) {
        if (!(std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '@')) {
            return false;
        }
    }
    return true;
}

bool load_boot_preset_file(const std::string& path, std::set<std::string>& presets, std::vector<ConfigIssue>* issues) {
    if (access(path.c_str(), F_OK) != 0) {
        return true;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        if (issues) {
            add_issue(*issues, "ERR", "Could not open boot preset file " + path);
        }
        return false;
    }

    std::string line;
    size_t line_number = 0;
    while (std::getline(file, line)) {
        ++line_number;
        std::string trimmed = trim_copy_local(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }

        bool remove = false;
        if (trimmed[0] == '-') {
            remove = true;
            trimmed = trim_copy_local(trimmed.substr(1));
        }

        if (!is_valid_service_ref(trimmed)) {
            if (issues) {
                add_issue(
                    *issues,
                    "ERR",
                    path + ":" + std::to_string(line_number) + ": invalid service name '" + trimmed + "'"
                );
            }
            continue;
        }

        if (remove) {
            presets.erase(trimmed);
        } else {
            presets.insert(trimmed);
        }
    }

    return true;
}

void scan_service_dir(
    const std::string& dir,
    bool persistent_enabled,
    std::map<std::string, LocalServiceInfo>& services,
    std::vector<ConfigIssue>& issues
) {
    DIR* directory = opendir(dir.c_str());
    if (!directory) {
        if (errno != ENOENT) {
            add_issue(issues, "ERR", "Could not open service directory " + dir + ": " + std::strerror(errno));
        }
        return;
    }

    std::vector<std::string> filenames;
    struct dirent* entry = nullptr;
    while ((entry = readdir(directory)) != nullptr) {
        const std::string filename = entry->d_name;
        if (filename.empty() || filename[0] == '.' || !has_gservice_suffix(filename)) {
            continue;
        }
        filenames.push_back(filename);
    }
    closedir(directory);

    std::sort(filenames.begin(), filenames.end());
    for (const auto& filename : filenames) {
        const std::string path = dir + "/" + filename;
        std::string error;
        std::optional<ginit::GService> parsed = ginit::GServiceParser::parse_file(path, &error);
        if (!parsed) {
            add_issue(issues, "ERR", path + ": " + error);
            continue;
        }

        LocalServiceInfo& slot = services[parsed->name];
        if (!slot.source_path.empty() && slot.source_path != path && !persistent_enabled) {
            add_issue(
                issues,
                "WARN",
                "Service '" + parsed->name + "' is declared more than once; keeping " + slot.source_path
            );
            continue;
        }

        slot.config = std::move(*parsed);
        if (persistent_enabled || slot.source_path.empty()) {
            slot.source_path = path;
        }
        slot.persistent_enabled = slot.persistent_enabled || persistent_enabled;
    }
}

std::set<std::string> load_boot_presets(std::vector<ConfigIssue>& issues) {
    std::set<std::string> presets;
    load_boot_preset_file(VENDOR_BOOT_SERVICES_PATH, presets, &issues);
    load_boot_preset_file(ADMIN_BOOT_SERVICES_PATH, presets, &issues);
    return presets;
}

std::map<std::string, LocalServiceInfo> load_local_service_catalog(std::vector<ConfigIssue>& issues) {
    std::map<std::string, LocalServiceInfo> services;
    scan_service_dir(AVAILABLE_SERVICES_DIR, false, services, issues);
    scan_service_dir(SYSTEM_SERVICES_DIR, true, services, issues);

    const std::set<std::string> presets = load_boot_presets(issues);
    for (const auto& name : presets) {
        auto it = services.find(name);
        if (it == services.end()) {
            add_issue(issues, "ERR", "Boot preset references unknown service '" + name + "'");
            continue;
        }
        it->second.preset_enabled = true;
    }

    return services;
}

void validate_service_relationships(
    const LocalServiceInfo& service,
    const std::map<std::string, LocalServiceInfo>& services,
    std::vector<ConfigIssue>& issues
) {
    for (const auto& dependency : service.config.required_services) {
        if (services.find(dependency) == services.end()) {
            add_issue(
                issues,
                "ERR",
                "Service '" + service.config.name + "' requires missing service '" + dependency + "'"
            );
        }
    }

    for (const auto& dependency : service.config.after) {
        if (services.find(dependency) == services.end()) {
            add_issue(
                issues,
                "WARN",
                "Service '" + service.config.name + "' orders after missing service '" + dependency + "'"
            );
        }
    }

    for (const auto& dependency : service.config.wants) {
        if (services.find(dependency) == services.end()) {
            add_issue(
                issues,
                "WARN",
                "Service '" + service.config.name + "' wants missing service '" + dependency + "'"
            );
        }
    }

    if (!service.config.env_file.empty() && access(service.config.env_file.c_str(), F_OK) != 0) {
        add_issue(
            issues,
            "WARN",
            "Service '" + service.config.name + "' references missing env file " + service.config.env_file
        );
    }
}

std::string render_offline_service_details(const LocalServiceInfo& service) {
    std::string out;
    out += "Service: " + service.config.name + "\n";
    out += "  Status: Unknown (offline inspection)\n";
    out += "  Enabled: ";
    out += (service.persistent_enabled || service.preset_enabled) ? "Yes\n" : "No\n";
    out += "  Persistent: ";
    out += service.persistent_enabled ? "Yes\n" : "No\n";
    out += "  Boot preset: ";
    out += service.preset_enabled ? "Yes\n" : "No\n";
    out += "  Description: " + service.config.description + "\n";
    if (!service.source_path.empty()) {
        out += "  Source: " + service.source_path + "\n";
    }
    out += "  Type: ";
    out += service.config.type == ginit::ServiceType::Oneshot ? "oneshot\n" : "simple\n";
    out += "  Restart policy: ";
    if (service.config.restart_policy == ginit::RestartPolicy::Always) {
        out += "always\n";
    } else if (service.config.restart_policy == ginit::RestartPolicy::OnFailure) {
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
        out += "  After: " + join_strings_local(service.config.after) + "\n";
    }
    if (!service.config.required_services.empty()) {
        out += "  Requires: " + join_strings_local(service.config.required_services) + "\n";
    }
    if (!service.config.wants.empty()) {
        out += "  Wants: " + join_strings_local(service.config.wants) + "\n";
    }
    out += "  Log file: /var/log/ginit/" + service.config.name + ".log\n";
    if (!service.config.start_pre.empty()) {
        out += "  StartPre: " + service.config.start_pre + "\n";
    }
    out += "  Start: " + service.config.start + "\n";
    if (!service.config.stop.empty()) {
        out += "  Stop: " + service.config.stop + "\n";
    }
    return out;
}

bool print_local_service_details(const std::string& service_name) {
    std::vector<ConfigIssue> issues;
    const std::map<std::string, LocalServiceInfo> services = load_local_service_catalog(issues);
    for (const auto& issue : issues) {
        if (issue.severity == "ERR") {
            std::cerr << "[" << issue.severity << "] " << issue.message << std::endl;
        }
    }

    auto it = services.find(service_name);
    if (it == services.end()) {
        std::cerr << "Service '" << service_name << "' not found." << std::endl;
        return false;
    }

    std::cout << render_offline_service_details(it->second);
    return true;
}

bool run_local_configuration_check(const std::string& service_name) {
    std::vector<ConfigIssue> issues;
    const std::map<std::string, LocalServiceInfo> services = load_local_service_catalog(issues);

    size_t checked_services = 0;
    if (!service_name.empty()) {
        auto it = services.find(service_name);
        if (it == services.end()) {
            add_issue(issues, "ERR", "Service '" + service_name + "' not found.");
        } else {
            validate_service_relationships(it->second, services, issues);
            checked_services = 1;
        }
    } else {
        for (const auto& entry : services) {
            validate_service_relationships(entry.second, services, issues);
        }
        checked_services = services.size();
    }

    std::set<std::string> presets;
    load_boot_preset_file(VENDOR_BOOT_SERVICES_PATH, presets, nullptr);
    load_boot_preset_file(ADMIN_BOOT_SERVICES_PATH, presets, nullptr);

    size_t error_count = 0;
    size_t warning_count = 0;
    for (const auto& issue : issues) {
        if (issue.severity == "ERR") {
            ++error_count;
        } else if (issue.severity == "WARN") {
            ++warning_count;
        }
    }

    std::cout << "ginit configuration check:" << std::endl;
    std::cout << "  [OK] loaded " << services.size() << " service definition(s)" << std::endl;
    std::cout << "  [OK] merged " << presets.size() << " boot preset entries" << std::endl;
    if (!service_name.empty() && checked_services == 1) {
        std::cout << "  [OK] checked service '" << service_name << "'" << std::endl;
    } else {
        std::cout << "  [OK] checked " << checked_services << " service(s)" << std::endl;
    }

    for (const auto& issue : issues) {
        if (issue.severity == "ERR") {
            std::cout << "  [ERR] " << issue.message << std::endl;
        } else if (issue.severity == "WARN") {
            std::cout << "  [WARN] " << issue.message << std::endl;
        }
    }

    if (error_count == 0 && warning_count == 0) {
        std::cout << "Summary: configuration looks good" << std::endl;
    } else if (error_count == 0) {
        std::cout << "Summary: warnings detected (" << warning_count << " warning(s))" << std::endl;
    } else {
        std::cout << "Summary: problems detected (" << error_count << " error(s), "
                  << warning_count << " warning(s))" << std::endl;
    }
    return error_count == 0;
}

std::string render_offline_service_status(const LocalServiceInfo& service) {
    std::string out = "Service: " + service.config.name + "\n";
    out += "  Runtime: unknown (ginit control socket unavailable)\n";
    out += "  Enabled at boot: " + std::string((service.persistent_enabled || service.preset_enabled) ? "yes" : "no") + "\n";
    if (service.persistent_enabled) {
        out += "  Enable source: persistent\n";
    } else if (service.preset_enabled) {
        out += "  Enable source: boot preset\n";
    } else {
        out += "  Enable source: not enabled\n";
    }
    out += "  Source: " + service.source_path + "\n";
    return out;
}

bool print_local_status(const std::string& service_name) {
    std::vector<ConfigIssue> issues;
    const std::map<std::string, LocalServiceInfo> services = load_local_service_catalog(issues);

    if (!service_name.empty()) {
        auto it = services.find(service_name);
        if (it == services.end()) {
            std::cerr << "Service '" << service_name << "' not found." << std::endl;
            return false;
        }
        std::cout << render_offline_service_status(it->second);
        return true;
    }

    if (services.empty()) {
        std::cout << "No ginit services were found." << std::endl;
        return true;
    }

    std::cout << "ginit offline status (runtime state unavailable):" << std::endl;
    for (const auto& entry : services) {
        const LocalServiceInfo& service = entry.second;
        std::cout << "  "
                  << ((service.persistent_enabled || service.preset_enabled) ? "[enabled] " : "[disabled] ")
                  << service.config.name;
        if (service.persistent_enabled) {
            std::cout << " (persistent)";
        } else if (service.preset_enabled) {
            std::cout << " (preset)";
        }
        std::cout << std::endl;
    }
    return true;
}

bool should_try_local_cli_fallback(const std::string& cmd, const std::string& error) {
    if (error.find("No control socket was found") != std::string::npos) {
        return true;
    }
    if (error.find("control socket exists but is not accepting commands") != std::string::npos) {
        return cmd == "status" || cmd == "show" || cmd == "enable" || cmd == "disable";
    }
    return false;
}

int run_local_cli_fallback(const std::string& cmd, const std::string& service) {
    if (cmd == "status") {
        return print_local_status(service) ? 0 : 1;
    }
    if (cmd == "show") {
        return print_local_service_details(service) ? 0 : 1;
    }
    if (cmd == "enable" || cmd == "disable") {
        ginit::GServiceManager local_manager;
        std::string response = (cmd == "enable")
            ? local_manager.enable_service(service)
            : local_manager.disable_service(service);
        std::cout << response;
        return response_indicates_failure(response) ? 1 : 0;
    }
    if (cmd == "start") {
        ginit::GServiceManager local_manager;
        local_manager.load_services_from_dir(SYSTEM_SERVICES_DIR, true);
        std::cerr << "Warning: ginit control socket is unavailable; performing an emergency local start." << std::endl;
        std::cerr << "         The service will run, but it will not be supervised by PID 1 until control is restored." << std::endl;
        const std::string response = local_manager.start_service(service);
        std::cout << response;
        return response_indicates_failure(response) ? 1 : 0;
    }
    return -1;
}

void apply_boot_presets(ginit::GServiceManager& manager) {
    std::vector<ConfigIssue> issues;
    const std::set<std::string> presets = load_boot_presets(issues);

    for (const auto& issue : issues) {
        std::cerr << "[GINIT] [" << issue.severity << "] " << issue.message << std::endl;
    }

    for (const auto& preset : presets) {
        const std::string result = manager.preset_service(preset);
        if (response_indicates_failure(result)) {
            std::cerr << "[GINIT] " << trim_copy_local(result) << std::endl;
        }
    }
}

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

std::string wait_status_to_string_local(int status) {
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

bool kernel_cmdline_has_flag(const std::string& flag) {
    std::ifstream cmdline("/proc/cmdline");
    if (!cmdline.is_open()) {
        return false;
    }

    std::string content;
    std::getline(cmdline, content);
    std::istringstream input(content);
    std::string token;
    while (input >> token) {
        if (token == flag) {
            return true;
        }
    }
    return false;
}

bool boot_verbose_enabled() {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    if (kernel_cmdline_has_flag("geminios.verbose_boot=1")) {
        cached = 1;
        return true;
    }
    if (kernel_cmdline_has_flag("geminios.verbose_boot=0")) {
        cached = 0;
        return false;
    }

    cached = kernel_cmdline_has_flag("quiet") ? 0 : 1;
    return cached != 0;
}

void boot_log_info(const std::string& message) {
    if (boot_verbose_enabled()) {
        std::cout << message << std::endl;
    }
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

void best_effort_restorecon_paths(const std::vector<std::string>& paths, bool recursive) {
    const std::string restorecon = find_first_existing_path({
        "/usr/sbin/restorecon",
        "/sbin/restorecon",
    });
    if (restorecon.empty()) {
        return;
    }

    std::vector<std::string> args = {"-F"};
    if (recursive) {
        args.push_back("-R");
    }
    for (const auto& path : paths) {
        if (access(path.c_str(), F_OK) == 0) {
            args.push_back(path);
        }
    }
    if (args.size() <= (recursive ? 2u : 1u)) {
        return;
    }

    int rc = run_helper_command(restorecon, args);
    if (rc != 0) {
        std::cerr << "[GINIT] restorecon failed with exit code " << rc << std::endl;
    }
}

std::string current_selinux_context() {
    char* context = nullptr;
    if (getcon(&context) != 0 || !context) {
        return "";
    }

    std::string result = context;
    freecon(context);
    return result;
}

bool reexec_after_selinux_transition(char* argv[]) {
    if (!argv || !argv[0] || !*argv[0]) {
        return false;
    }

    const std::string reexec_path = find_first_existing_path({
        "/usr/bin/ginit",
        "/bin/ginit",
        argv[0],
    });
    if (reexec_path.empty()) {
        return false;
    }

    if (boot_verbose_enabled()) {
        std::cerr << "[GINIT] Re-execing PID 1 through " << reexec_path << " for SELinux domain transition." << std::endl;
    }

    setenv("GINIT_SELINUX_REEXECED", "1", 1);
    execv(reexec_path.c_str(), argv);
    perror("[GINIT] Failed to re-exec after SELinux policy load");
    return false;
}

void configure_selinux_runtime(char* argv[]) {
    const bool is_live = is_live_environment();
    const bool selinux_disabled = kernel_cmdline_has_flag("selinux=0");

    if (is_live || selinux_disabled) {
        return;
    }

    auto config = load_os_release_fields("/etc/selinux/config");
    std::string mode = to_lower_copy_local(release_field_or(config, "SELINUX", "disabled"));
    std::string policy_name = trim_copy_local(release_field_or(config, "SELINUXTYPE", "default"));

    if (mode == "disabled") {
        return;
    }

    const bool reexeced = getenv("GINIT_SELINUX_REEXECED") != nullptr;
    if (!reexeced) {
        if (boot_verbose_enabled()) {
            const std::string before = current_selinux_context();
            if (!before.empty()) {
                std::cerr << "[GINIT] SELinux context before policy load: " << before << std::endl;
            }
        }
        int enforce = (mode == "enforcing") ? 1 : 0;
        if (selinux_init_load_policy(&enforce) == 0) {
            best_effort_restorecon_paths({
                "/usr/bin/ginit",
                "/usr/bin/ginit-netcfg",
                "/bin/ginit",
                "/bin/ginit-netcfg",
                "/usr/sbin/init",
                "/sbin/init",
                "/usr/bin/login",
                "/usr/sbin/agetty",
                "/sbin/agetty",
            }, false);
            if (reexec_after_selinux_transition(argv)) {
                return;
            }
        } else if (is_selinux_enabled() > 0) {
            std::cerr << "[GINIT] SELinux policy initialization failed; continuing without PID 1 relabel transition." << std::endl;
        }
    }

    unsetenv("GINIT_SELINUX_REEXECED");
    if (is_selinux_enabled() <= 0) {
        return;
    }

    if (boot_verbose_enabled()) {
        const std::string after = current_selinux_context();
        if (!after.empty()) {
            std::cerr << "[GINIT] SELinux context after policy load: " << after << std::endl;
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
                boot_log_info("[GINIT] Completed SELinux relabel pass.");
            } else {
                std::cerr << "[GINIT] SELinux relabel pass failed with exit code " << rc << std::endl;
            }
        }
    }

    best_effort_restorecon_paths({
        "/dev",
        "/run",
        "/tmp",
        "/var/log",
        "/var/tmp",
        "/var/lib",
        "/home",
        "/root",
        "/etc",
    }, true);
}

// Mount filesystems and ensure target directory exists
void mount_fs(const char* source, const char* target, const char* fs_type) {
    mkdir(target, 0755);
    if (mount(source, target, fs_type, 0, NULL) == 0) {
        boot_log_info(std::string("[OK] Mounted ") + target);
    } else {
        if (errno == EBUSY) {
            boot_log_info(std::string("[OK] ") + target + " already mounted");
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
        "/sys/fs",
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
        release["PRETTY_NAME"] = OS_NAME;
        release["VERSION_ID"] = OS_VERSION_ID;
        release["VERSION_CODENAME"] = OS_CODENAME;
        release["ANSI_COLOR"] = OS_ANSI_COLOR;
        release["LOGO"] = "distributor-logo-geminios";
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
            f << "LOGO=\"" << release["LOGO"] << "\"\n";
            f << "HOME_URL=\"" << release["HOME_URL"] << "\"\n";
            f << "SUPPORT_URL=\"" << release["SUPPORT_URL"] << "\"\n";
            f << "BUG_REPORT_URL=\"" << release["BUG_REPORT_URL"] << "\"\n";
            f.close();
            boot_log_info("[GINIT] Generated fallback /etc/os-release");
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
        boot_log_info("[GINIT] Generated /etc/lsb-release");
    }

    if (access("/etc/hostname", F_OK) == -1) {
        std::ofstream hn("/etc/hostname");
        if (hn) {
            hn << "geminios-pc\n";
            hn.close();
            sethostname("geminios-pc", 11);
            boot_log_info("[GINIT] Set hostname to geminios-pc");
        }
    } else {
        std::ifstream hn("/etc/hostname");
        std::string name;
        if (hn >> name) sethostname(name.c_str(), name.length());
    }

    std::ofstream issue("/etc/issue");
    if (issue) {
        if (is_live_environment()) {
            issue << pretty_name << " Live Session\n";
            issue << "Host: \\n\n";
            issue << "Welcome to " << pretty_name << ".\n";
            issue << "You are running the system from live media.\n";
            issue << "Run 'installer' as root to install " << OS_NAME << " to disk.\n";
            issue << "TTY: \\l\n\n";
        } else {
            issue << pretty_name << "\n\\l\n\n";
        }
        issue.close();
    }
}

struct TtySupervisor {
    const char* tty = nullptr;
    pid_t pid = -1;
    int failure_count = 0;
    bool emergency_shell = false;
};

bool install_signal_handler(int sig, void (*handler)(int)) {
    struct sigaction action {};
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(sig, &action, nullptr) != 0) {
        perror(("[GINIT] sigaction failed for signal " + std::to_string(sig)).c_str());
        return false;
    }
    return true;
}

void pid1_signal_handler(int sig) {
    if (sig == SIGCHLD) {
        g_child_event = 1;
        return;
    }
    g_stop_sig = sig;
}

[[noreturn]] void handle_shutdown_signal() {
    if (g_stop_sig == SIGINT) {
        std::cerr << "[GINIT] Rebooting..." << std::endl;
        sync();
        reboot(RB_AUTOBOOT);
    }

    std::cerr << "[GINIT] Powering off..." << std::endl;
    sync();
    reboot(RB_POWER_OFF);
    _exit(1);
}

bool ensure_symlink(const char* target, const char* linkpath) {
    if (symlink(target, linkpath) == 0 || errno == EEXIST) {
        return true;
    }
    perror(("[GINIT] Failed to create symlink " + std::string(linkpath)).c_str());
    return false;
}

pid_t spawn_getty(const char* tty, const char* autologin_user = nullptr) {
    const std::string agetty_path = find_first_existing_path({
        "/usr/sbin/agetty",
        "/sbin/agetty",
    });
    if (!agetty_path.empty()) {
        std::string line = tty ? tty : "";
        if (line.rfind("/dev/", 0) == 0) {
            line.erase(0, 5);
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror(("[GINIT] fork failed while spawning agetty for " + std::string(tty)).c_str());
            return -1;
        }

        if (pid == 0) {
            std::vector<std::string> args_storage;
            args_storage.push_back("agetty");
            args_storage.push_back("--noclear");
            args_storage.push_back("--keep-baud");
            args_storage.push_back("--login-program");
            args_storage.push_back("/usr/bin/login");
            if (autologin_user && *autologin_user) {
                args_storage.push_back("--autologin");
                args_storage.push_back(autologin_user);
            }
            args_storage.push_back(line);
            args_storage.push_back("115200,38400,9600");
            args_storage.push_back("linux");

            std::vector<char*> argv;
            argv.reserve(args_storage.size() + 1);
            for (auto& arg : args_storage) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);

            execv(agetty_path.c_str(), argv.data());
            perror(("execv " + agetty_path).c_str());
            _exit(127);
        }

        return pid;
    }

    std::cerr << "[GINIT] util-linux agetty not found; refusing to spawn legacy getty fallback." << std::endl;
    errno = ENOENT;
    return -1;
}

pid_t spawn_emergency_shell(const char* tty) {
    const std::string shell_path = find_first_existing_path({
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/sh",
        "/usr/bin/sh",
    });
    if (shell_path.empty()) {
        errno = ENOENT;
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror(("[GINIT] fork failed while spawning emergency shell for " + std::string(tty)).c_str());
        return -1;
    }

    if (pid == 0) {
        const int fd = open(tty, O_RDWR | O_NOCTTY);
        if (fd < 0) {
            perror(("[GINIT] open failed while spawning emergency shell for " + std::string(tty)).c_str());
            _exit(127);
        }

        setsid();
        if (ioctl(fd, TIOCSCTTY, 1) < 0) {
            perror("[GINIT] ioctl TIOCSCTTY failed for emergency shell");
        }
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) {
            close(fd);
        }

        setenv("USER", "root", 1);
        setenv("LOGNAME", "root", 1);
        setenv("HOME", "/root", 1);
        setenv("SHELL", shell_path.c_str(), 1);
        setenv("PATH", "/bin/apps/system:/bin/apps:/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin", 1);

        std::fprintf(stderr, "\n[GINIT] Emergency console started on %s.\n", tty);

        const char* shell_name = shell_path.find("bash") != std::string::npos ? "bash" : "sh";
        if (shell_path.find("bash") != std::string::npos) {
            execl(shell_path.c_str(), shell_name, "-l", nullptr);
        } else {
            execl(shell_path.c_str(), shell_name, nullptr);
        }
        perror(("execv " + shell_path).c_str());
        _exit(127);
    }

    return pid;
}

void ensure_tty_running(TtySupervisor& tty, bool is_live) {
    if (tty.pid > 0) {
        return;
    }

    if (tty.emergency_shell) {
        tty.pid = spawn_emergency_shell(tty.tty);
    } else {
        tty.pid = spawn_getty(tty.tty, is_live ? "root" : nullptr);
    }
    if (tty.pid <= 0) {
        std::cerr << "[GINIT] Failed to spawn " << (tty.emergency_shell ? "emergency shell" : "getty")
                  << " for " << tty.tty << std::endl;
        if (!is_live && !tty.emergency_shell && std::string(tty.tty) == "/dev/ttyS0") {
            tty.emergency_shell = true;
            tty.pid = spawn_emergency_shell(tty.tty);
            if (tty.pid > 0) {
                std::cerr << "[GINIT] Switched " << tty.tty << " to emergency shell after getty startup failure." << std::endl;
            } else {
                std::cerr << "[GINIT] Failed to spawn emergency shell for " << tty.tty << std::endl;
            }
        }
    }
}

bool handle_tty_exit(pid_t pid, int status, std::array<TtySupervisor, 4>& terminals, bool is_live) {
    for (auto& tty : terminals) {
        if (tty.pid != pid) {
            continue;
        }

        tty.pid = -1;
        if (std::string(tty.tty) == "/dev/ttyS0" && !is_live) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                tty.failure_count = 0;
            } else {
                ++tty.failure_count;
                if (tty.failure_count >= 1) {
                    tty.emergency_shell = true;
                    std::cerr << "[GINIT] Serial getty exited with " << wait_status_to_string_local(status)
                              << "; starting emergency shell on " << tty.tty << std::endl;
                }
            }
        }
        ensure_tty_running(tty, is_live);
        return true;
    }
    return false;
}

void reap_children(std::array<TtySupervisor, 4>& terminals, bool is_live) {
    while (true) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0) {
            if (service_manager.is_managed_process(pid)) {
                service_manager.handle_process_death(pid, status);
            } else if (!handle_tty_exit(pid, status, terminals, is_live)) {
                if (boot_verbose_enabled()) {
                    std::cerr << "[GINIT] Reaped untracked child PID " << pid << std::endl;
                }
            }
            continue;
        }

        if (pid == 0) {
            return;
        }

        if (errno == EINTR) {
            continue;
        }
        if (errno != ECHILD) {
            perror("[GINIT] waitpid");
        }
        return;
    }
}

void show_help() {
    std::cout << "GeminiOS Init System (ginit) CLI" << std::endl;
    std::cout << "Usage: ginit <command> [service]" << std::endl;
    std::cout << "\nCommands:" << std::endl;
    std::cout << "  status [service]   Show status of all services or a specific one" << std::endl;
    std::cout << "  show <service>     Show detailed service configuration and boot policy" << std::endl;
    std::cout << "  check [service]    Validate service files and boot preset configuration" << std::endl;
    std::cout << "  start <service>    Start a service" << std::endl;
    std::cout << "  stop <service>     Stop a service" << std::endl;
    std::cout << "  restart <service>  Restart a service" << std::endl;
    std::cout << "  enable <service>   Enable a service to start at boot" << std::endl;
    std::cout << "  disable <service>  Disable a service from starting at boot" << std::endl;
    std::cout << "  help               Show this help message" << std::endl;
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    const std::string invoked_as = basename_copy_local(argv[0]);
    const bool invoked_as_ginit = (invoked_as == "ginit");

    if (getpid() == 1) {
        if (setenv("PATH", "/bin:/usr/bin:/sbin:/usr/sbin:/bin/apps/system:/bin/apps", 1) != 0) {
            perror("[GINIT] setenv(PATH)");
        }
        install_signal_handler(SIGINT, pid1_signal_handler);
        install_signal_handler(SIGTERM, pid1_signal_handler);
        install_signal_handler(SIGPWR, pid1_signal_handler);
        install_signal_handler(SIGCHLD, pid1_signal_handler);
        signal(SIGPIPE, SIG_IGN);
    }

    if (getpid() != 1) {
        if (argc < 2) {
            if (invoked_as_ginit) {
                show_help();
                return 0;
            } else {
                std::cerr << "This binary is the GeminiOS init entry point." << std::endl;
                std::cerr << "Use 'ginit <command>' for service management." << std::endl;
            }
            return 1;
        }

        std::string cmd = argv[1];
        if (cmd == "help" || cmd == "--help" || cmd == "-h") {
            if (invoked_as_ginit) {
                show_help();
                return 0;
            }
            std::cerr << "Use 'ginit help' to view the ginit CLI." << std::endl;
            return 1;
        }

        std::string service = (argc > 2) ? argv[2] : "";
        
        // Commands that REQUIRE a service name
        if (cmd == "start" || cmd == "stop" || cmd == "restart" || cmd == "enable" || cmd == "disable" || cmd == "show") {
            if (service.empty()) {
                std::cerr << "Error: Command '" << cmd << "' requires a service name." << std::endl;
                std::cerr << "Usage: ginit " << cmd << " <service>" << std::endl;
                return 1;
            }
        }

        if (cmd == "check") {
            return run_local_configuration_check(service) ? 0 : 1;
        }

        if (cmd == "show") {
            std::string response;
            std::string error;
            if (ginit::GServiceManager::send_command(cmd + " " + service, &response, &error)) {
                std::cout << response;
                return response_indicates_failure(response) ? 1 : 0;
            }
            if (!should_try_local_cli_fallback(cmd, error)) {
                if (!error.empty()) {
                    std::cerr << error << std::endl;
                }
                return 1;
            }
            return run_local_cli_fallback(cmd, service);
        }

        if (cmd == "status" || cmd == "start" || cmd == "stop" || cmd == "restart" || cmd == "enable" || cmd == "disable") {
            std::string response;
            std::string error;
            if (!ginit::GServiceManager::send_command(cmd + " " + service, &response, &error)) {
                if (should_try_local_cli_fallback(cmd, error)) {
                    const int fallback_rc = run_local_cli_fallback(cmd, service);
                    if (fallback_rc >= 0) {
                        return fallback_rc;
                    }
                }
                if (!error.empty()) {
                    std::cerr << error << std::endl;
                }
                return 1;
            }
            std::cout << response;
            return response_indicates_failure(response) ? 1 : 0;
        }

        std::cerr << "Unknown command: " << cmd << std::endl;
        if (invoked_as_ginit) {
            show_help();
        } else {
            std::cerr << "Use 'ginit help' to view the ginit CLI." << std::endl;
        }
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

    safe_mkdir("/var/lib/dbus");
    safe_mkdir("/run/dbus");

    ensure_symlink("/proc/self/fd", "/dev/fd");
    ensure_symlink("/proc/self/fd/0", "/dev/stdin");
    ensure_symlink("/proc/self/fd/1", "/dev/stdout");
    ensure_symlink("/proc/self/fd/2", "/dev/stderr");

    UserMgmt::initialize_defaults();
    generate_os_release();

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

    configure_selinux_runtime(argv);

    if (!service_manager.start_ipc_server()) {
        std::cerr << "[GINIT] IPC server could not be started early; retrying after service startup." << std::endl;
    }

    if (boot_verbose_enabled()) {
        std::cerr << "[GINIT] Loading enabled system services..." << std::endl;
    }
    service_manager.load_services_from_dir(SYSTEM_SERVICES_DIR, true);

    if (boot_verbose_enabled()) {
        std::cerr << "[GINIT] Applying boot presets..." << std::endl;
    }
    apply_boot_presets(service_manager);

    if (boot_verbose_enabled()) {
        std::cerr << "[GINIT] Starting system services..." << std::endl;
    }
    service_manager.start_enabled_services();
    if (service_manager.ipc_server_fd() < 0 && !service_manager.start_ipc_server()) {
        std::cerr << "[GINIT] IPC server could not be started; CLI control will be unavailable." << std::endl;
    }

    std::array<TtySupervisor, 4> terminals = {{
        {"/dev/tty1", -1},
        {"/dev/tty2", -1},
        {"/dev/tty3", -1},
        {"/dev/ttyS0", -1},
    }};

    const bool is_live = is_live_environment();
    for (auto& tty : terminals) {
        ensure_tty_running(tty, is_live);
    }

    while (true) {
        if (g_stop_sig) {
            handle_shutdown_signal();
        }

        reap_children(terminals, is_live);
        g_child_event = 0;

        const int server_fd = service_manager.ipc_server_fd();
        if (server_fd < 0) {
            pause();
            continue;
        }

        struct pollfd pfd {};
        pfd.fd = server_fd;
        pfd.events = POLLIN;

        int rc = poll(&pfd, 1, -1);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("[GINIT] poll");
            sleep(1);
            continue;
        }

        if (pfd.revents & POLLIN) {
            service_manager.accept_pending_ipc_clients();
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            std::cerr << "[GINIT] Restarting IPC server after socket error." << std::endl;
            service_manager.shutdown_ipc_server();
            service_manager.start_ipc_server();
        }
    }
}
