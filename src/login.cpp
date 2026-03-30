#include <algorithm>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <grp.h>
#include <iostream>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <vector>
#include "sys_info.h"

namespace {

void set_default_env(const char* name, const std::string& value) {
    const char* current = getenv(name);
    if (!current || *current == '\0') {
        setenv(name, value.c_str(), 1);
    }
}

std::string prompt_input(const std::string& prompt, bool echo) {
    if (!prompt.empty()) {
        std::cout << prompt;
        std::cout.flush();
    }

    std::string value;
    if (echo) {
        std::getline(std::cin, value);
        return value;
    }

    struct termios current {};
    if (tcgetattr(STDIN_FILENO, &current) != 0) {
        std::getline(std::cin, value);
        std::cout << std::endl;
        return value;
    }

    struct termios original = current;
    current.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &current);
    std::getline(std::cin, value);
    tcsetattr(STDIN_FILENO, TCSANOW, &original);
    std::cout << std::endl;
    return value;
}

void free_pam_responses(pam_response* responses, int num_msg) {
    if (!responses) {
        return;
    }

    for (int index = 0; index < num_msg; ++index) {
        free(responses[index].resp);
    }
    free(responses);
}

int conversation(int num_msg, const pam_message** msg, pam_response** resp, void*) {
    if (num_msg <= 0 || !msg || !resp) {
        return PAM_CONV_ERR;
    }

    auto responses = static_cast<pam_response*>(calloc(static_cast<size_t>(num_msg), sizeof(pam_response)));
    if (!responses) {
        return PAM_BUF_ERR;
    }

    for (int index = 0; index < num_msg; ++index) {
        const pam_message* current = msg[index];
        if (!current) {
            free_pam_responses(responses, num_msg);
            return PAM_CONV_ERR;
        }

        std::string prompt = current->msg ? current->msg : "";
        switch (current->msg_style) {
            case PAM_PROMPT_ECHO_ON: {
                std::string answer = prompt_input(prompt, true);
                responses[index].resp = strdup(answer.c_str());
                break;
            }
            case PAM_PROMPT_ECHO_OFF: {
                std::string answer = prompt_input(prompt, false);
                responses[index].resp = strdup(answer.c_str());
                break;
            }
            case PAM_ERROR_MSG:
                if (!prompt.empty()) {
                    std::cerr << prompt << std::endl;
                }
                break;
            case PAM_TEXT_INFO:
                if (!prompt.empty()) {
                    std::cout << prompt << std::endl;
                }
                break;
            default:
                free_pam_responses(responses, num_msg);
                return PAM_CONV_ERR;
        }

        if ((current->msg_style == PAM_PROMPT_ECHO_ON || current->msg_style == PAM_PROMPT_ECHO_OFF) &&
            !responses[index].resp) {
            free_pam_responses(responses, num_msg);
            return PAM_BUF_ERR;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;
}

void set_base_environment(const passwd& user) {
    const std::string home = (user.pw_dir && *user.pw_dir) ? user.pw_dir : "/";

    setenv("USER", user.pw_name, 1);
    setenv("LOGNAME", user.pw_name, 1);
    setenv("HOME", home.c_str(), 1);
    setenv("SHELL", (user.pw_shell && *user.pw_shell) ? user.pw_shell : "/bin/bash", 1);
    setenv("PATH", "/bin/apps/system:/bin/apps:/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin", 1);
    set_default_env("TERM", "linux");
    set_default_env("XDG_CONFIG_DIRS", "/etc/xdg");
    set_default_env("XDG_DATA_DIRS", "/usr/local/share:/usr/share");
    set_default_env("XDG_CONFIG_HOME", home + "/.config");
    set_default_env("XDG_CACHE_HOME", home + "/.cache");
    set_default_env("XDG_DATA_HOME", home + "/.local/share");
    set_default_env("XDG_STATE_HOME", home + "/.local/state");
    set_default_env("XDG_SESSION_CLASS", "user");
}

void import_pam_environment(pam_handle_t* pamh) {
    char** pam_env = pam_getenvlist(pamh);
    if (!pam_env) {
        return;
    }

    for (char** current = pam_env; *current; ++current) {
        std::string entry = *current;
        size_t delimiter = entry.find('=');
        if (delimiter != std::string::npos) {
            setenv(entry.substr(0, delimiter).c_str(), entry.substr(delimiter + 1).c_str(), 1);
        }
        free(*current);
    }
    free(pam_env);
}

std::string default_runtime_dir(const passwd& user) {
    return "/run/user/" + std::to_string(user.pw_uid);
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

std::string find_restorecon_binary() {
    static const char* candidates[] = {
        "/usr/sbin/restorecon",
        "/sbin/restorecon",
    };

    for (const char* candidate : candidates) {
        if (access(candidate, X_OK) == 0) {
            return candidate;
        }
    }
    return "";
}

void best_effort_restorecon(const std::string& path) {
    if (access("/etc/geminios-live", F_OK) == 0 || kernel_cmdline_has_flag("selinux=0")) {
        return;
    }

    const std::string restorecon = find_restorecon_binary();
    if (restorecon.empty() || path.empty()) {
        return;
    }

    const pid_t child = fork();
    if (child == 0) {
        execl(restorecon.c_str(), restorecon.c_str(), "-F", path.c_str(), nullptr);
        _exit(127);
    }
    if (child < 0) {
        return;
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return;
        }
    }
}

void ensure_runtime_dir_privileged(const passwd& user) {
    std::string runtime_dir = default_runtime_dir(user);
    if (mkdir("/run/user", 0755) != 0 && errno != EEXIST) {
        perror("mkdir /run/user");
    }
    if (mkdir(runtime_dir.c_str(), 0700) != 0 && errno != EEXIST) {
        perror("mkdir XDG_RUNTIME_DIR");
    }
    if (chown(runtime_dir.c_str(), user.pw_uid, user.pw_gid) != 0) {
        perror("chown XDG_RUNTIME_DIR");
    }
    chmod(runtime_dir.c_str(), 0700);
    best_effort_restorecon(runtime_dir);
}

void ensure_directory_path(const std::string& path) {
    if (path.empty()) {
        return;
    }

    std::string current;
    if (path.front() == '/') {
        current = "/";
    }

    size_t index = current == "/" ? 1 : 0;
    while (index <= path.size()) {
        size_t next_sep = path.find('/', index);
        std::string component = path.substr(index, next_sep == std::string::npos ? std::string::npos : next_sep - index);
        if (!component.empty()) {
            if (current.size() > 1 && current.back() != '/') {
                current += "/";
            }
            current += component;
            if (mkdir(current.c_str(), 0700) != 0 && errno != EEXIST) {
                perror(("mkdir " + current).c_str());
                return;
            }
        }
        if (next_sep == std::string::npos) {
            break;
        }
        index = next_sep + 1;
    }
}

void ensure_user_xdg_dirs() {
    const char* directories[] = {
        getenv("XDG_CONFIG_HOME"),
        getenv("XDG_CACHE_HOME"),
        getenv("XDG_DATA_HOME"),
        getenv("XDG_STATE_HOME"),
    };

    for (const char* path : directories) {
        if (path && *path) {
            ensure_directory_path(path);
        }
    }
}

void adopt_runtime_dbus_address() {
    const char* runtime_dir = getenv("XDG_RUNTIME_DIR");
    if (!runtime_dir || *runtime_dir == '\0') {
        return;
    }
    if (getenv("DBUS_SESSION_BUS_ADDRESS") != nullptr) {
        return;
    }

    const std::string bus_path = std::string(runtime_dir) + "/bus";
    struct stat st {};
    if (stat(bus_path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
        setenv("DBUS_SESSION_BUS_ADDRESS", ("unix:path=" + bus_path).c_str(), 1);
    }
}

void prepare_user_session(const passwd& user, pam_handle_t* pamh) {
    set_base_environment(user);
    import_pam_environment(pamh);

    const std::string runtime_dir = default_runtime_dir(user);
    const char* current_runtime_dir = getenv("XDG_RUNTIME_DIR");
    if (!current_runtime_dir || *current_runtime_dir == '\0' || access(current_runtime_dir, F_OK) != 0) {
        if (access(runtime_dir.c_str(), F_OK) == 0) {
            setenv("XDG_RUNTIME_DIR", runtime_dir.c_str(), 1);
        }
    }
    ensure_user_xdg_dirs();
    adopt_runtime_dbus_address();
}

int run_shell_session(const passwd& user, pam_handle_t* pamh) {
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        ensure_runtime_dir_privileged(user);
        if (initgroups(user.pw_name, user.pw_gid) != 0) {
            perror("initgroups");
            _exit(1);
        }
        if (setgid(user.pw_gid) != 0) {
            perror("setgid");
            _exit(1);
        }
        if (setuid(user.pw_uid) != 0) {
            perror("setuid");
            _exit(1);
        }

        prepare_user_session(user, pamh);

        if (chdir(user.pw_dir) != 0 && chdir("/") != 0) {
            perror("chdir");
        }

        std::string shell = user.pw_shell && *user.pw_shell ? user.pw_shell : "/bin/bash";
        std::string shell_name = "-" + shell.substr(shell.find_last_of('/') + 1);
        char* const argv[] = {
            const_cast<char*>(shell_name.c_str()),
            nullptr,
        };
        execv(shell.c_str(), argv);
        perror("execv shell");
        _exit(1);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            perror("waitpid");
            return 1;
        }
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

int authenticate_and_run(const std::string& initial_user, bool autologin) {
    std::string requested_user = initial_user;
    if (requested_user.empty()) {
        std::cout << OS_NAME << " login: ";
        std::cout.flush();
        if (!std::getline(std::cin, requested_user) || requested_user.empty()) {
            return std::cin.eof() ? 0 : 1;
        }
    }

    pam_conv conv = {
        .conv = conversation,
        .appdata_ptr = nullptr,
    };

    const char* service_name = autologin ? "login-autologin" : "login";
    pam_handle_t* pamh = nullptr;
    int pam_result = pam_start(service_name, requested_user.c_str(), &conv, &pamh);
    if (pam_result != PAM_SUCCESS) {
        std::cerr << "PAM startup failed: " << pam_strerror(pamh, pam_result) << std::endl;
        if (pamh) {
            pam_end(pamh, pam_result);
        }
        return 1;
    }

    const char* tty = ttyname(STDIN_FILENO);
    if (tty) {
        pam_set_item(pamh, PAM_TTY, tty);
    }

    pam_putenv(pamh, const_cast<char*>("XDG_SESSION_CLASS=user"));
    pam_putenv(pamh, const_cast<char*>("XDG_SESSION_TYPE=tty"));
    pam_putenv(pamh, const_cast<char*>("XDG_CURRENT_DESKTOP=TTY"));
    pam_putenv(pamh, const_cast<char*>("XDG_SESSION_DESKTOP=tty"));

    pam_result = pam_authenticate(pamh, 0);
    if (pam_result == PAM_SUCCESS) {
        pam_result = pam_acct_mgmt(pamh, 0);
    }
    if (pam_result == PAM_NEW_AUTHTOK_REQD) {
        pam_result = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
    }
    if (pam_result != PAM_SUCCESS) {
        std::cout << "Login incorrect" << std::endl;
        pam_end(pamh, pam_result);
        return 1;
    }

    pam_result = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (pam_result == PAM_SUCCESS) {
        pam_result = pam_open_session(pamh, 0);
    }
    if (pam_result != PAM_SUCCESS) {
        std::cerr << "Session setup failed: " << pam_strerror(pamh, pam_result) << std::endl;
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, pam_result);
        return 1;
    }

    const void* pam_user_item = nullptr;
    pam_result = pam_get_item(pamh, PAM_USER, &pam_user_item);
    if (pam_result != PAM_SUCCESS || !pam_user_item) {
        std::cerr << "PAM did not return a user." << std::endl;
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, pam_result);
        return 1;
    }

    const char* pam_user = static_cast<const char*>(pam_user_item);
    passwd* pw = getpwnam(pam_user);
    if (!pw) {
        std::cerr << "User lookup failed for " << pam_user << std::endl;
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, pam_result);
        return 1;
    }

    passwd session_user = *pw;
    int shell_status = run_shell_session(session_user, pamh);

    int close_result = pam_close_session(pamh, 0);
    int cred_result = pam_setcred(pamh, PAM_DELETE_CRED);
    if (close_result != PAM_SUCCESS) {
        std::cerr << "Failed to close PAM session: " << pam_strerror(pamh, close_result) << std::endl;
    }
    if (cred_result != PAM_SUCCESS) {
        std::cerr << "Failed to drop PAM credentials: " << pam_strerror(pamh, cred_result) << std::endl;
    }
    pam_end(pamh, close_result != PAM_SUCCESS ? close_result : cred_result);

    return shell_status;
}

} // namespace

int main(int argc, char* argv[]) {
    std::string username;
    bool autologin = false;

    for (int index = 1; index < argc; ++index) {
        std::string arg = argv[index];
        if (arg == "-f" && index + 1 < argc) {
            username = argv[index + 1];
            autologin = true;
            ++index;
        } else if (username.empty()) {
            username = arg;
        }
    }

    while (true) {
        int result = authenticate_and_run(username, autologin);
        if (result == 0 && std::cin.eof()) {
            return 0;
        }
        if (result != 0 && !autologin) {
            sleep(2);
        }
        username.clear();
        autologin = false;
    }
}
