#include <iostream>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <fstream>
#include <sstream>
#include "sys_info.h"

namespace {

bool kernel_cmdline_has_token(const std::string& token) {
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

bool getty_verbose_enabled() {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
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

void debug_log(const std::string& message) {
    if (getty_verbose_enabled()) {
        std::cerr << message << std::endl;
    }
}

void debug_log_stdout(const std::string& message) {
    if (getty_verbose_enabled()) {
        std::cout << message << std::endl;
    }
}

} // namespace

int main(int argc, char* argv[]) {
    debug_log("[GETTY] Starting...");
    
    if (argc < 2) {
        std::cerr << "Usage: getty <tty> [autologin_user]" << std::endl;
        return 1;
    }

    std::string tty_dev = argv[1];
    std::string autologin_user;
    if (argc > 2) {
        autologin_user = argv[2];
    }

    if (tty_dev.find("/dev/") != 0) {
        tty_dev = "/dev/" + tty_dev;
    }
    
    if (getty_verbose_enabled()) {
        std::cerr << "[GETTY] Target TTY: " << tty_dev << std::endl;
        std::cerr << std::flush;
    }

    // Open TTY
    // Use O_NOCTTY to avoid acquiring it as controlling tty immediately
    // We will do it manually with TIOCSCTTY
    if (getty_verbose_enabled()) {
        std::cerr << "[GETTY] Opening " << tty_dev << "..." << std::endl;
        std::cerr << std::flush;
    }
    int fd = open(tty_dev.c_str(), O_RDWR | O_NOCTTY);
    if (fd < 0) {
        perror("[GETTY] open tty failed");
        return 1;
    }
    debug_log("[GETTY] Opened " + tty_dev + " (fd: " + std::to_string(fd) + ")");

    // Set TERM environment variable
    setenv("TERM", "linux", 1);

    // Manage controlling terminal
    ioctl(fd, TIOCNOTTY); // Detach from current if any
    setsid();
    if (ioctl(fd, TIOCSCTTY, 1) < 0) {
        perror("getty: ioctl TIOCSCTTY");
    }
    debug_log("[GETTY] Controlling terminal set.");

    // Setup standard FDs
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2) close(fd);

    // Write debug message to kmsg
    int kmsg = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (kmsg >= 0) {
        std::string msg = "getty: started on " + tty_dev + "\n";
        write(kmsg, msg.c_str(), msg.length());
        close(kmsg);
    }
    
    debug_log_stdout("[GETTY] Banner printing...");

    // Basic termios setup (similar to ginit's previous logic)
    struct termios t;
    tcgetattr(STDIN_FILENO, &t);
    t.c_cc[VINTR] = 3;   // Ctrl+C
    t.c_cc[VQUIT] = 28;  // Ctrl+Backslash
    t.c_cc[VERASE] = 127;
    t.c_cc[VKILL] = 21;
    t.c_cc[VEOF] = 4;
    t.c_cc[VSTART] = 17;
    t.c_cc[VSTOP] = 19;
    t.c_cc[VSUSP] = 26;
    t.c_lflag |= (ISIG | ICANON | ECHO | ECHOE | ECHOK);
    tcsetattr(STDIN_FILENO, TCSANOW, &t);

    // Print banner
    std::cout << "\033[2J\033[1;1H"; // Clear screen
    std::cout << std::flush;
    
    std::ifstream issue("/etc/issue");
    if (issue) {
        std::string line;
        std::string tty_name = tty_dev;
        if (tty_name.find("/dev/") == 0) {
            tty_name = tty_name.substr(5);
        }
        
        char hostname[256];
        std::string host_str = "GeminiOS";
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            host_str = hostname;
        }

        while (std::getline(issue, line)) {
            // Remove trailing \r if present (for Windows-style line endings)
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            std::string parsed_line = "";
            for (size_t i = 0; i < line.length(); ++i) {
                if (line[i] == '\\' && i + 1 < line.length()) {
                    char next = line[i + 1];
                    switch (next) {
                        case 'l': parsed_line += tty_name; break;
                        case 'n': parsed_line += host_str; break;
                        case 's': parsed_line += OS_NAME; break;
                        case 'v': parsed_line += OS_VERSION; break;
                        case '\\': parsed_line += '\\'; break;
                        default: 
                            parsed_line += line[i]; 
                            parsed_line += next; 
                            break;
                    }
                    i++; 
                } else {
                    parsed_line += line[i];
                }
            }
            std::cout << parsed_line << std::endl;
        }
    } else {
        std::cout << OS_NAME << " " << OS_VERSION << " (" << OS_ARCH << ")" << std::endl;
        std::cout << tty_dev << std::endl << std::endl;
    }
    std::cout << std::flush;

    // Execute login
    if (!autologin_user.empty()) {
        char* const login_argv[] = { (char*)"/usr/bin/login", (char*)"-f", (char*)autologin_user.c_str(), nullptr };
        execv("/usr/bin/login", login_argv);
    } else {
        char* const login_argv[] = { (char*)"/usr/bin/login", nullptr };
        execv("/usr/bin/login", login_argv);
    }

    perror("getty: execv /usr/bin/login");
    return 1;
}
