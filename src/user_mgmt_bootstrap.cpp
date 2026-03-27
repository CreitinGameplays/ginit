#include "user_mgmt.h"

#include <cerrno>
#include <crypt.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

namespace {

std::string default_root_hash() {
    // A fixed salt keeps the bootstrap helper tiny while still storing a real
    // SHA-512 crypt hash instead of a plaintext password in /etc/shadow.
    static constexpr const char* kSalt = "$6$geminios$";
    char* hashed = crypt("root", kSalt);
    if (!hashed) {
        std::cerr << "[INIT] crypt() failed while creating default root password: "
                  << std::strerror(errno) << std::endl;
        return "!";
    }
    return hashed;
}

} // namespace

void UserMgmt::initialize_defaults() {
    if (access("/etc/passwd", F_OK) != 0) {
        std::cout << "[INIT] Creating default /etc/passwd..." << std::endl;
        std::ofstream passwd("/etc/passwd");
        if (passwd) {
            passwd << "root:x:0:0:System Administrator:/root:/bin/bash\n";
        } else {
            std::cerr << "[INIT] Failed to create /etc/passwd" << std::endl;
        }
    }

    if (access("/etc/shadow", F_OK) != 0) {
        std::cout << "[INIT] Creating default /etc/shadow..." << std::endl;
        std::ofstream shadow("/etc/shadow");
        if (shadow) {
            shadow << "root:" << default_root_hash() << ":19000:0:99999:7:::" << "\n";
            shadow.close();
            if (chmod("/etc/shadow", 0600) != 0) {
                std::cerr << "[INIT] chmod(/etc/shadow) failed: " << std::strerror(errno) << std::endl;
            }
        } else {
            std::cerr << "[INIT] Failed to create /etc/shadow" << std::endl;
        }
    }

    if (access("/etc/group", F_OK) != 0) {
        std::cout << "[INIT] Creating default /etc/group..." << std::endl;
        std::ofstream group("/etc/group");
        if (group) {
            group << "root:x:0:\n";
            group << "sudo:x:27:root\n";
            group << "users:x:100:\n";
        } else {
            std::cerr << "[INIT] Failed to create /etc/group" << std::endl;
        }
    }

    if (mkdir("/root", 0700) != 0 && errno != EEXIST) {
        std::cerr << "[INIT] mkdir(/root) failed: " << std::strerror(errno) << std::endl;
    }
    if (mkdir("/home", 0755) != 0 && errno != EEXIST) {
        std::cerr << "[INIT] mkdir(/home) failed: " << std::strerror(errno) << std::endl;
    }
}
