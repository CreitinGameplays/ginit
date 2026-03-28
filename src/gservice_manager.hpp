#ifndef GSERVICE_MANAGER_HPP
#define GSERVICE_MANAGER_HPP

#include "gservice_parser.hpp"

#include <string>
#include <vector>
#include <sys/types.h>

namespace ginit {

struct ServiceState {
    GService config;
    std::string source_path;
    std::string last_result;
    pid_t pid = -1;
    int restart_count = 0;
    bool persistent_enabled = false;
    bool preset_enabled = false;
    bool running = false;
    bool finished_successfully = false;
    bool stopping = false;
    bool starting = false;
};

class GServiceManager {
public:
    GServiceManager();
    ~GServiceManager();

    void load_services_from_dir(const std::string& dir, bool enabled);
    std::string start_service(const std::string& name);
    std::string stop_service(const std::string& name);
    std::string restart_service(const std::string& name);

    std::string enable_service(const std::string& name);
    std::string disable_service(const std::string& name);
    std::string preset_service(const std::string& name);

    void start_enabled_services();

    void handle_process_death(pid_t pid, int status);
    bool is_managed_process(pid_t pid) const;

    void print_status();
    std::string get_status_str() const;
    void print_service_status(const std::string& name);
    std::string get_service_details_str(const std::string& name) const;

    bool start_ipc_server();
    void accept_pending_ipc_clients();
    void shutdown_ipc_server();
    int ipc_server_fd() const;

    static bool send_command(const std::string& command, std::string* response = nullptr, std::string* error = nullptr);
    static bool control_socket_present(std::string* path = nullptr);

private:
    std::vector<ServiceState> services_;
    int ipc_server_fd_ = -1;
    std::string socket_path_;

    static constexpr const char* SYSTEM_SERVICES_DIR = "/etc/ginit/services/system";
    static constexpr const char* AVAILABLE_SERVICES_DIR = "/usr/lib/ginit/services";

    ServiceState* find_service(const std::string& name);
    const ServiceState* find_service(const std::string& name) const;
    ServiceState* find_service_by_pid(pid_t pid);
    bool load_service_file(const std::string& path, bool persistent_enabled, ServiceState** out_state = nullptr);
    ServiceState* load_service_by_name(const std::string& name, bool persistent_enabled);
    bool load_service_snapshot(const std::string& name, ServiceState& out_state, std::string* error) const;
    static bool is_enabled(const ServiceState& service);

    pid_t spawn_process(const GService& config);
    bool apply_environment(const GService& config, std::string* error);
    bool apply_security(const GService& config, std::string* error);
    int run_shell_command(const GService& config, const std::string& command, const std::string& log_file);
    std::string service_log_path(const std::string& service_name) const;
    bool wait_for_service_exit(ServiceState& service, pid_t expected_pid, uint32_t timeout_ms, std::string* detail);

    void handle_ipc_client(int client_fd);
    std::string handle_command(const std::string& command);
    std::string status_for_service(const ServiceState& service) const;
    std::string detail_for_service(const ServiceState& service) const;
    std::vector<size_t> get_service_order() const;
    void visit(size_t index, std::vector<unsigned char>& state, std::vector<size_t>& order) const;

    static bool write_all(int fd, const char* data, size_t length);
};

} // namespace ginit

#endif // GSERVICE_MANAGER_HPP
