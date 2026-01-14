#include <iostream>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <fstream>
#include "sys_info.h"

int main(int argc, char* argv[]) {
    // Immediate debug to console (inherited from ginit)
    std::cerr << "[GETTY] Starting..." << std::endl;
    
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
    
    std::cerr << "[GETTY] Target TTY: " << tty_dev << std::endl;

    // Open TTY
    // Use O_NOCTTY to avoid acquiring it as controlling tty immediately
    // We will do it manually with TIOCSCTTY
    std::cerr << "[GETTY] Opening " << tty_dev << "..." << std::endl;
    int fd = open(tty_dev.c_str(), O_RDWR | O_NOCTTY);
    if (fd < 0) {
        perror("[GETTY] open tty failed");
        return 1;
    }
    std::cerr << "[GETTY] Opened " << tty_dev << " (fd: " << fd << ")" << std::endl;

    // Set TERM environment variable
    setenv("TERM", "linux", 1);

    // Manage controlling terminal
    ioctl(fd, TIOCNOTTY); // Detach from current if any
    setsid();
    if (ioctl(fd, TIOCSCTTY, 1) < 0) {
        perror("getty: ioctl TIOCSCTTY");
    }
    std::cerr << "[GETTY] Controlling terminal set." << std::endl;

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
    
    std::cout << "[GETTY] Banner printing..." << std::endl;

    // Basic termios setup (similar to ginit's previous logic)
    struct termios t;
    tcgetattr(STDIN_FILENO, &t);
    t.c_cc[VINTR] = 3;   // Ctrl+C
    t.c_cc[VQUIT] = 28;  // Ctrl+\
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
        while (std::getline(issue, line)) {
            // Very basic replacement for \n, \l etc could be added here
            std::cout << line << std::endl;
        }
    } else {
        std::cout << OS_NAME << " " << OS_VERSION << " (" << OS_ARCH << ")" << std::endl;
    }
    std::cout << tty_dev << std::endl << std::endl;
    std::cout << std::flush;

    // Execute login
    if (!autologin_user.empty()) {
        char* const login_argv[] = { (char*)"/bin/login", (char*)"-f", (char*)autologin_user.c_str(), nullptr };
        execv("/bin/login", login_argv);
    } else {
        char* const login_argv[] = { (char*)"/bin/login", nullptr };
        execv("/bin/login", login_argv);
    }

    perror("getty: execv /bin/login");
    return 1;
}
