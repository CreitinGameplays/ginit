#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <termios.h>
#include <cstring>
#include <algorithm>
#include <fstream>
#include "user_mgmt.h"
#include "sys_info.h"
#include "signals.h"

void set_env(const User& u) {
    setenv("USER", u.username.c_str(), 1);
    setenv("LOGNAME", u.username.c_str(), 1);
    setenv("HOME", u.home.c_str(), 1);
    setenv("SHELL", u.shell.c_str(), 1);
    setenv("PATH", "/bin/apps/system:/bin/apps:/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin", 1);
    setenv("TERM", "linux", 0); // Don't override if already set
    
    std::string xdg_runtime = "/run/user/" + std::to_string(u.uid);
    setenv("XDG_RUNTIME_DIR", xdg_runtime.c_str(), 1);
    
    // Ensure runtime dir exists (usually handled by PAM or systemd, but we do it here for now)
    mkdir("/run/user", 0755);
    mkdir(xdg_runtime.c_str(), 0700);
    chown(xdg_runtime.c_str(), u.uid, u.gid);
}

int main(int argc, char* argv[]) {
    std::string username;
    bool autologin = false;

    // Argument parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-f") {
            if (i + 1 < argc) {
                username = argv[i+1];
                autologin = true;
                i++; // Skip username arg
            }
        } else if (username.empty()) {
            username = arg;
        }
    }

    while (true) {
        std::vector<User> users;
        bool authenticated = false;
        User authenticated_user;

        if (UserMgmt::load_users(users)) {
            // Check if user exists first
            bool user_found = false;
            for (const auto& u : users) {
                if (u.username == username) {
                    authenticated_user = u;
                    user_found = true;
                    break;
                }
            }
            
            if (autologin && user_found) {
                authenticated = true;
            } else {
                // Normal Login Flow
                if (username.empty()) {
                    std::cout << OS_NAME << " login: ";
                    if (!std::getline(std::cin, username) || username.empty()) {
                        if (std::cin.eof()) return 0;
                        continue;
                    }
                    // Re-check user existence after getting username
                    if (UserMgmt::load_users(users)) {
                         for (const auto& u : users) {
                            if (u.username == username) {
                                authenticated_user = u;
                                user_found = true;
                                break;
                            }
                        }
                    }
                }

                // Disable Echo for password
                struct termios t;
                tcgetattr(STDIN_FILENO, &t);
                struct termios oldt = t;
                t.c_lflag &= ~ECHO;
                tcsetattr(STDIN_FILENO, TCSANOW, &t);

                std::string password;
                std::cout << "Password: ";
                if (!std::getline(std::cin, password)) {
                    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                    return 0;
                }

                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                std::cout << std::endl;
                
                if (user_found && UserMgmt::check_password(password, authenticated_user.password)) {
                    authenticated = true;
                }
            }
        }

        if (authenticated) {
            // Setup session
            if (initgroups(authenticated_user.username.c_str(), authenticated_user.gid) != 0) {
                perror("initgroups");
            }
            if (setgid(authenticated_user.gid) != 0) {
                perror("setgid");
            }
            if (setuid(authenticated_user.uid) != 0) {
                perror("setuid");
                exit(1);
            }

            set_env(authenticated_user);

            if (chdir(authenticated_user.home.c_str()) != 0) {
                if (chdir("/") != 0) {
                    perror("chdir /");
                }
            }

            // Execute shell as login shell (argv[0] starts with -)
            std::string shell = authenticated_user.shell;
            if (shell.empty()) shell = "/bin/bash";

            std::string shell_name = "-" + shell.substr(shell.find_last_of("/") + 1);
            char* const shell_argv[] = { (char*)shell_name.c_str(), nullptr };
            execv(shell.c_str(), shell_argv);
            
            // If execv returns, it failed
            perror("execv shell");
            exit(1);
        } else {
            std::cout << "Login incorrect" << std::endl;
            sleep(2);
            username.clear(); // Prompt again
            autologin = false; // Disable autologin on failure (though it shouldn't fail if user exists)
        }
    }

    return 0;
}
