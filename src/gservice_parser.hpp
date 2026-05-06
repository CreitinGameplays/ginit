#ifndef GSERVICE_PARSER_HPP
#define GSERVICE_PARSER_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ginit {

enum class ServiceType : uint8_t {
    Simple,
    Oneshot,
};

enum class RestartPolicy : uint8_t {
    Never,
    OnFailure,
    Always,
};

struct EnvVar {
    std::string name;
    std::string value;
};

struct GService {
    std::string name;
    std::string description;
    std::vector<std::string> after;
    std::vector<std::string> wants;
    std::vector<std::string> required_services;
    std::string user;
    std::string group;
    std::string work_dir;
    std::string env_file;
    std::vector<EnvVar> env_vars;
    std::string start_pre;
    std::string start;
    std::string stop;
    bool no_new_privileges = false;
    bool failure_is_fatal = true;
    ServiceType type = ServiceType::Simple;
    RestartPolicy restart_policy = RestartPolicy::Never;
    uint32_t restart_delay_us = 0;
    uint32_t stop_timeout_ms = 5000;
};

class GServiceParser {
public:
    static std::optional<GService> parse_file(const std::string& filename, std::string* error = nullptr);
    static std::optional<GService> parse_string(const std::string& content, std::string* error = nullptr);

    struct Token {
        enum Type {
            Identifier,
            String,
            Number,
            LBrace,
            RBrace,
            LBracket,
            RBracket,
            Equals,
            Comma,
            EndOfFile,
            Error,
        } type = EndOfFile;

        std::string value;
        size_t line = 1;
        size_t column = 1;
    };

private:
    class Lexer {
    public:
        explicit Lexer(const std::string& input);
        Token next_token();

    private:
        const std::string& input_;
        size_t pos_ = 0;
        size_t line_ = 1;
        size_t column_ = 1;

        char peek(size_t offset = 0) const;
        char advance();
        void skip_whitespace_and_comments();
    };

    class Parser {
    public:
        explicit Parser(Lexer& lexer);
        std::optional<GService> parse();
        const std::string& error_message() const;

    private:
        Lexer& lexer_;
        Token current_token_;
        std::string error_;

        void next_token();
        bool expect(Token::Type type, const char* expected);
        bool expect_identifier(const char* expected);
        bool parse_service(GService& service);
        bool parse_meta(GService& service);
        bool parse_deps(GService& service);
        bool parse_process(GService& service);
        bool parse_commands(GService& service);
        bool parse_lifecycle(GService& service);
        bool parse_env(GService& service);
        bool parse_vars(GService& service);
        bool parse_security(GService& service);
        bool parse_install();
        bool parse_resources();
        bool parse_string_list(std::vector<std::string>& values);
        bool parse_value(std::string& value);
        bool skip_value();
        bool skip_block();
        bool skip_list();
        bool parse_bool_value(bool& out);
        bool parse_duration_us(uint32_t& out);
        bool parse_duration_ms(uint32_t& out);
        void set_error(const std::string& message);
        std::string location_prefix() const;
    };
};

} // namespace ginit

#endif // GSERVICE_PARSER_HPP
