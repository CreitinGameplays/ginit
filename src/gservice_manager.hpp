#ifndef GSERVICE_MANAGER_HPP
#define GSERVICE_MANAGER_HPP

#include "gservice_parser.hpp"
#include <map>
#include <vector>
#include <string>
#include <memory>
#include <sys/types.h>

namespace ginit {

struct ServiceState {
    std::unique_ptr<GService> config;
    pid_t pid = -1;
    int restart_count = 0;
    bool enabled = false;
    bool running = false;
    bool finished_successfully = false;
};

class GServiceManager {
public:
    GServiceManager();
    
    void load_services_from_dir(const std::string& dir);
    std::string start_service(const std::string& name);
    std::string stop_service(const std::string& name);
    std::string restart_service(const std::string& name);
    
    // Persistence
    std::string enable_service(const std::string& name);
    std::string disable_service(const std::string& name);

    void start_enabled_services();
    
    // Process supervision
    void handle_process_death(pid_t pid, int status);
    bool is_managed_process(pid_t pid) const;

    // CLI Actions
    void print_status();
    std::string get_status_str();
    void print_service_status(const std::string& name);

    // IPC
    void run_ipc_server();
    static void send_command(const std::string& command);

private:
    std::map<std::string, ServiceState> services;
    std::map<pid_t, std::string> pid_to_name;
    const std::string SYSTEM_SERVICES_DIR = "/etc/ginit/services/system";
    const std::string AVAILABLE_SERVICES_DIR = "/usr/lib/ginit/services";

    pid_t spawn_process(const GService& config);
    void setup_environment(const GService& config);
    void setup_security(const GService& config);
    
    void handle_ipc_client(int client_fd);

    // Dependency management
    std::vector<std::string> get_service_order();
    void visit(const std::string& name, std::map<std::string, bool>& visited, std::map<std::string, bool>& stack, std::vector<std::string>& order);
};

} // namespace ginit

#endif // GSERVICE_MANAGER_HPP
