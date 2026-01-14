#ifndef GSERVICE_PARSER_HPP
#define GSERVICE_PARSER_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace ginit {

struct Meta {
    std::string description;
    std::string docs;
    struct Deps {
        std::vector<std::string> after;
        std::vector<std::string> wants;
        std::vector<std::string> requires;
    } deps;
};

struct Process {
    std::string type;
    std::string user;
    std::string group;
    std::string work_dir;
    struct Commands {
        std::string start_pre;
        std::string start;
        std::string reload;
        std::string stop;
    } commands;
    struct Lifecycle {
        std::string restart_policy;
        std::string restart_delay;
        std::string stop_timeout;
    } lifecycle;
};

struct Env {
    std::string load_file;
    std::map<std::string, std::string> vars;
};

struct Security {
    bool no_new_privileges = false;
    std::string protect_system;
    bool protect_home = false;
    bool private_tmp = false;
    std::vector<std::string> rw_paths;
};

struct Resources {
    int ulimit_nofile = 0;
    std::string memory_max;
    std::string cpu_quota;
};

struct Install {
    std::vector<std::string> wanted_by;
    std::string alias;
};

struct GService {
    std::string name;
    Meta meta;
    Process process;
    Env env;
    Security security;
    Resources resources;
    Install install;
};

class GServiceParser {
public:
    static std::unique_ptr<GService> parse_file(const std::string& filename);
    static std::unique_ptr<GService> parse_string(const std::string& content);

private:
    struct Token {
        enum Type {
            IDENTIFIER,
            STRING,
            NUMBER,
            LBRACE,
            RBRACE,
            LBRACKET,
            RBRACKET,
            EQUALS,
            COMMA,
            END_OF_FILE,
            ERROR
        } type;
        std::string value;
    };

    class Lexer {
    public:
        Lexer(const std::string& input);
        Token next_token();
    private:
        std::string input;
        size_t pos = 0;
        void skip_whitespace_and_comments();
    };

    class Parser {
    public:
        Parser(Lexer& lexer);
        std::unique_ptr<GService> parse();
    private:
        Lexer& lexer;
        Token current_token;

        void next_token();
        bool match(Token::Type type);
        bool expect(Token::Type type);

        void parse_service(GService& service);
        void parse_meta(Meta& meta);
        void parse_deps(Meta::Deps& deps);
        void parse_process(Process& process);
        void parse_commands(Process::Commands& commands);
        void parse_lifecycle(Process::Lifecycle& lifecycle);
        void parse_env(Env& env);
        void parse_vars(std::map<std::string, std::string>& vars);
        void parse_security(Security& security);
        void parse_resources(Resources& resources);
        void parse_install(Install& install);

        std::vector<std::string> parse_string_list();
        std::string parse_value();
    };
};

} // namespace ginit

#endif // GSERVICE_PARSER_HPP
