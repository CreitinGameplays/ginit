#ifndef USER_MGMT_H
#define USER_MGMT_H

#include <string>
#include <vector>
#include <sys/types.h>

struct User {
    std::string username;
    std::string password; // Hash
    uid_t uid;
    gid_t gid;
    std::string gecos;
    std::string home;
    std::string shell;
};

struct Group {
    std::string name;
    std::string password;
    gid_t gid;
    std::vector<std::string> members;
};

class UserMgmt {
public:
    static bool load_users(std::vector<User>& users);
    static bool save_users(const std::vector<User>& users);
    
    static bool load_shadow(std::vector<User>& users);
    static bool save_shadow(const std::vector<User>& users);

    static bool load_groups(std::vector<Group>& groups);
    static bool save_groups(const std::vector<Group>& groups);

    static std::string hash_password(const std::string& plaintext);
    static bool check_password(const std::string& plaintext, const std::string& hash);
    
    static int get_next_uid(const std::vector<User>& users);
    static int get_next_gid(const std::vector<Group>& groups);

    static bool is_valid_username(const std::string& username);

    static void initialize_defaults();
};

#endif