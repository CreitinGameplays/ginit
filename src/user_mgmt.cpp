#include "user_mgmt.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <crypt.h>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <random>

// Helper string split
std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    // Handle trailing delimiter or empty fields
    if (!s.empty() && s.back() == delimiter) tokens.push_back("");
    return tokens;
}

bool UserMgmt::load_users(std::vector<User>& users) {
    users.clear();
    std::ifstream file("/etc/passwd");
    if (!file) return false;
    std::string line;
    while (std::getline(file, line)) {
        auto parts = split(line, ':');
        if (parts.size() >= 7) {
            User u;
            u.username = parts[0];
            u.uid = std::stoi(parts[2]);
            u.gid = std::stoi(parts[3]);
            u.gecos = parts[4];
            u.home = parts[5];
            u.shell = parts[6];
            users.push_back(u);
        }
    }
    // Load shadow passwords if possible
    load_shadow(users);
    return true;
}

bool UserMgmt::save_users(const std::vector<User>& users) {
    std::ofstream file("/etc/passwd");
    if (!file) return false;
    for (const auto& u : users) {
        file << u.username << ":x:" << u.uid << ":" << u.gid << ":" 
             << u.gecos << ":" << u.home << ":" << u.shell << "\n";
    }
    return true;
}

bool UserMgmt::load_shadow(std::vector<User>& users) {
    std::ifstream file("/etc/shadow");
    if (!file) return false;
    std::string line;
    while (std::getline(file, line)) {
        auto parts = split(line, ':');
        if (parts.size() >= 2) {
            for (auto& u : users) {
                if (u.username == parts[0]) {
                    u.password = parts[1];
                    break;
                }
            }
        }
    }
    return true;
}

bool UserMgmt::save_shadow(const std::vector<User>& users) {
    std::ofstream file("/etc/shadow");
    if (!file) return false;
    // Format: name:hash:lastchg:min:max:warn:inactive:expire
    long now = std::time(0) / 86400;
    for (const auto& u : users) {
        std::string pwd = u.password.empty() ? "!" : u.password;
        file << u.username << ":" << pwd << ":" << now << ":0:99999:7:::" << "\n";
    }
    return true;
}

bool UserMgmt::load_groups(std::vector<Group>& groups) {
    groups.clear();
    std::ifstream file("/etc/group");
    if (!file) return false;
    std::string line;
    while (std::getline(file, line)) {
        auto parts = split(line, ':');
        if (parts.size() >= 4) {
            Group g;
            g.name = parts[0];
            g.password = parts[1];
            g.gid = std::stoi(parts[2]);
            // Parse members
            std::stringstream ss(parts[3]);
            std::string member;
            while (std::getline(ss, member, ',')) {
                g.members.push_back(member);
            }
            groups.push_back(g);
        }
    }
    return true;
}

bool UserMgmt::save_groups(const std::vector<Group>& groups) {
    std::ofstream file("/etc/group");
    if (!file) return false;
    for (const auto& g : groups) {
        file << g.name << ":x:" << g.gid << ":";
        for (size_t i = 0; i < g.members.size(); ++i) {
            file << g.members[i] << (i == g.members.size() - 1 ? "" : ",");
        }
        file << "\n";
    }
    return true;
}

std::string UserMgmt::hash_password(const std::string& plaintext) {
    // Generate a random salt for SHA512
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    std::string salt = "$6$";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 63);
    
    for(int i = 0; i < 12; i++) {
        salt += charset[dis(gen)];
    }
    salt += "$";
    
    char* hashed = crypt(plaintext.c_str(), salt.c_str());
    if (hashed) return std::string(hashed);
    
    // Fallback if crypt fails (should not happen with libxcrypt)
    return "!";
}

// Keep old hash logic for verification of old passwords
std::string hash_password_old(const std::string& plaintext) {
    std::string salt = "GEMINI_SALT"; 
    std::string combined = salt + plaintext;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined.c_str(), combined.length(), hash);
    
    std::stringstream ss;
    ss << "$5$" << salt << "$";
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool UserMgmt::check_password(const std::string& plaintext, const std::string& hash) {
    if (hash.empty()) return plaintext.empty();
    if (hash == "!" || hash == "*") return false;

    // Check if it's the old custom hash
    if (hash.length() > 15 && hash.substr(0, 15) == "$5$GEMINI_SALT$") {
        return hash_password_old(plaintext) == hash;
    }

    // Standard crypt verification
    char* encrypted = crypt(plaintext.c_str(), hash.c_str());
    if (!encrypted) return false;
    return std::string(encrypted) == hash;
}

int UserMgmt::get_next_uid(const std::vector<User>& users) {
    int max_uid = 999; // Start regular users at 1000
    for (const auto& u : users) {
        if (u.uid > (uid_t)max_uid && u.uid < 65534) max_uid = u.uid;
    }
    return max_uid + 1;
}

int UserMgmt::get_next_gid(const std::vector<Group>& groups) {
    int max_gid = 999;
    for (const auto& g : groups) {
        if (g.gid > (gid_t)max_gid && g.gid < 65534) max_gid = g.gid;
    }
    return max_gid + 1;
}

bool UserMgmt::is_valid_username(const std::string& username) {
    if (username.length() < 4 || username.length() > 16) return false;
    for (char c : username) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
            return false;
        }
    }
    return true;
}

void UserMgmt::initialize_defaults() {
    if (access("/etc/passwd", F_OK) != 0) {
        std::cout << "[INIT] Creating default /etc/passwd..." << std::endl;
        std::ofstream p("/etc/passwd");
        // Root Account
        p << "root:x:0:0:System Administrator:/root:/bin/bash\n";
        p.close();
    }
    
    if (access("/etc/shadow", F_OK) != 0) {
        std::cout << "[INIT] Creating default /etc/shadow..." << std::endl;
        std::ofstream s("/etc/shadow");
        // Root password 'root'
        s << "root:" << hash_password("root") << ":19000:0:99999:7:::" << "\n";
        s.close();
        chmod("/etc/shadow", 0600);
    }

    if (access("/etc/group", F_OK) != 0) {
        std::cout << "[INIT] Creating default /etc/group..." << std::endl;
        std::ofstream g("/etc/group");
        g << "root:x:0:\n";
        g << "sudo:x:27:root\n"; // Add root to sudo
        g << "users:x:100:\n";
        g.close();
    }
    
    // Ensure home exists
    mkdir("/root", 0700);
    mkdir("/home", 0755);
}