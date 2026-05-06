#include "gservice_parser.hpp"

#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>
#include <utility>

namespace ginit {

namespace {

bool is_identifier_start(char ch) {
    const unsigned char value = static_cast<unsigned char>(ch);
    return std::isalpha(value) || ch == '_';
}

bool is_identifier_part(char ch) {
    const unsigned char value = static_cast<unsigned char>(ch);
    return std::isalnum(value) || ch == '_' || ch == '-';
}

bool is_value_token(GServiceParser::Token::Type type) {
    return type == GServiceParser::Token::String ||
           type == GServiceParser::Token::Number ||
           type == GServiceParser::Token::Identifier;
}

} // namespace

GServiceParser::Lexer::Lexer(const std::string& input) : input_(input) {}

char GServiceParser::Lexer::peek(size_t offset) const {
    const size_t index = pos_ + offset;
    if (index >= input_.size()) {
        return '\0';
    }
    return input_[index];
}

char GServiceParser::Lexer::advance() {
    if (pos_ >= input_.size()) {
        return '\0';
    }

    const char ch = input_[pos_++];
    if (ch == '\n') {
        ++line_;
        column_ = 1;
    } else {
        ++column_;
    }
    return ch;
}

void GServiceParser::Lexer::skip_whitespace_and_comments() {
    while (pos_ < input_.size()) {
        const char ch = peek();
        if (std::isspace(static_cast<unsigned char>(ch))) {
            advance();
            continue;
        }

        if (ch == '#') {
            while (peek() != '\0' && peek() != '\n') {
                advance();
            }
            continue;
        }

        if (ch == '/' && peek(1) == '/') {
            advance();
            advance();
            while (peek() != '\0' && peek() != '\n') {
                advance();
            }
            continue;
        }

        break;
    }
}

GServiceParser::Token GServiceParser::Lexer::next_token() {
    skip_whitespace_and_comments();

    Token token;
    token.line = line_;
    token.column = column_;

    const char ch = peek();
    if (ch == '\0') {
        token.type = Token::EndOfFile;
        return token;
    }

    if (is_identifier_start(ch)) {
        token.type = Token::Identifier;
        while (is_identifier_part(peek())) {
            token.value.push_back(advance());
        }
        return token;
    }

    if (std::isdigit(static_cast<unsigned char>(ch))) {
        token.type = Token::Number;
        while (std::isalnum(static_cast<unsigned char>(peek())) || peek() == '.') {
            token.value.push_back(advance());
        }
        return token;
    }

    if (ch == '"') {
        token.type = Token::String;
        advance();
        while (peek() != '\0' && peek() != '"') {
            if (peek() == '\\') {
                advance();
                const char escaped = advance();
                switch (escaped) {
                    case 'n':
                        token.value.push_back('\n');
                        break;
                    case 'r':
                        token.value.push_back('\r');
                        break;
                    case 't':
                        token.value.push_back('\t');
                        break;
                    case '"':
                    case '\\':
                        token.value.push_back(escaped);
                        break;
                    case '\0':
                        token.type = Token::Error;
                        token.value = "unterminated escape sequence";
                        return token;
                    default:
                        token.value.push_back(escaped);
                        break;
                }
            } else {
                token.value.push_back(advance());
            }
        }

        if (peek() != '"') {
            token.type = Token::Error;
            token.value = "unterminated string literal";
            return token;
        }

        advance();
        return token;
    }

    advance();
    switch (ch) {
        case '{':
            token.type = Token::LBrace;
            token.value = "{";
            return token;
        case '}':
            token.type = Token::RBrace;
            token.value = "}";
            return token;
        case '[':
            token.type = Token::LBracket;
            token.value = "[";
            return token;
        case ']':
            token.type = Token::RBracket;
            token.value = "]";
            return token;
        case '=':
            token.type = Token::Equals;
            token.value = "=";
            return token;
        case ',':
            token.type = Token::Comma;
            token.value = ",";
            return token;
        default:
            token.type = Token::Error;
            token.value.assign(1, ch);
            return token;
    }
}

GServiceParser::Parser::Parser(Lexer& lexer) : lexer_(lexer) {
    next_token();
}

const std::string& GServiceParser::Parser::error_message() const {
    return error_;
}

void GServiceParser::Parser::next_token() {
    current_token_ = lexer_.next_token();
    if (current_token_.type == Token::Error && error_.empty()) {
        set_error("lexer error: " + current_token_.value);
    }
}

void GServiceParser::Parser::set_error(const std::string& message) {
    if (error_.empty()) {
        error_ = location_prefix() + message;
    }
}

std::string GServiceParser::Parser::location_prefix() const {
    std::ostringstream out;
    out << "line " << current_token_.line << ", column " << current_token_.column << ": ";
    return out.str();
}

bool GServiceParser::Parser::expect(Token::Type type, const char* expected) {
    if (!error_.empty()) {
        return false;
    }
    if (current_token_.type != type) {
        set_error(std::string("expected ") + expected + ", got '" + current_token_.value + "'");
        return false;
    }
    next_token();
    return true;
}

bool GServiceParser::Parser::expect_identifier(const char* expected) {
    if (!error_.empty()) {
        return false;
    }
    if (current_token_.type != Token::Identifier || current_token_.value != expected) {
        set_error(std::string("expected identifier '") + expected + "'");
        return false;
    }
    next_token();
    return true;
}

bool GServiceParser::Parser::parse_value(std::string& value) {
    if (!error_.empty()) {
        return false;
    }
    if (!is_value_token(current_token_.type)) {
        set_error("expected a value");
        return false;
    }
    value = current_token_.value;
    next_token();
    return true;
}

bool GServiceParser::Parser::parse_bool_value(bool& out) {
    std::string value;
    if (!parse_value(value)) {
        return false;
    }

    if (value == "true" || value == "yes" || value == "1") {
        out = true;
        return true;
    }
    if (value == "false" || value == "no" || value == "0") {
        out = false;
        return true;
    }

    set_error("expected a boolean value");
    return false;
}

bool GServiceParser::Parser::parse_duration_us(uint32_t& out) {
    std::string raw;
    if (!parse_value(raw)) {
        return false;
    }

    if (raw.empty()) {
        set_error("expected a duration");
        return false;
    }

    size_t split = 0;
    while (split < raw.size() && std::isdigit(static_cast<unsigned char>(raw[split]))) {
        ++split;
    }
    if (split == 0) {
        set_error("expected a numeric duration");
        return false;
    }

    unsigned long long value = 0;
    for (size_t index = 0; index < split; ++index) {
        value = (value * 10ULL) + static_cast<unsigned long long>(raw[index] - '0');
        if (value > std::numeric_limits<uint32_t>::max()) {
            set_error("duration is too large");
            return false;
        }
    }

    const std::string unit = raw.substr(split);
    unsigned long long result = value;
    if (unit.empty() || unit == "s") {
        result = value * 1000000ULL;
    } else if (unit == "ms") {
        result = value * 1000ULL;
    } else if (unit == "us") {
        result = value;
    } else if (unit == "m") {
        result = value * 60ULL * 1000000ULL;
    } else if (unit == "h") {
        result = value * 60ULL * 60ULL * 1000000ULL;
    } else {
        set_error("unsupported duration unit '" + unit + "'");
        return false;
    }

    if (result > std::numeric_limits<uint32_t>::max()) {
        set_error("duration is too large");
        return false;
    }

    out = static_cast<uint32_t>(result);
    return true;
}

bool GServiceParser::Parser::parse_duration_ms(uint32_t& out) {
    uint32_t micros = 0;
    if (!parse_duration_us(micros)) {
        return false;
    }
    out = micros / 1000U;
    return true;
}

bool GServiceParser::Parser::parse_string_list(std::vector<std::string>& values) {
    if (!expect(Token::LBracket, "'['")) {
        return false;
    }

    while (current_token_.type != Token::RBracket && current_token_.type != Token::EndOfFile) {
        std::string value;
        if (!parse_value(value)) {
            return false;
        }
        values.push_back(std::move(value));

        if (current_token_.type == Token::Comma) {
            next_token();
        } else if (current_token_.type != Token::RBracket) {
            set_error("expected ',' or ']'");
            return false;
        }
    }

    return expect(Token::RBracket, "']'");
}

bool GServiceParser::Parser::skip_list() {
    if (!expect(Token::LBracket, "'['")) {
        return false;
    }

    int depth = 1;
    while (depth > 0 && current_token_.type != Token::EndOfFile) {
        if (current_token_.type == Token::LBracket) {
            ++depth;
        } else if (current_token_.type == Token::RBracket) {
            --depth;
        }
        next_token();
    }

    if (depth != 0) {
        set_error("unterminated list");
        return false;
    }
    return true;
}

bool GServiceParser::Parser::skip_block() {
    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    int depth = 1;
    while (depth > 0 && current_token_.type != Token::EndOfFile) {
        if (current_token_.type == Token::LBrace) {
            ++depth;
        } else if (current_token_.type == Token::RBrace) {
            --depth;
        }
        next_token();
    }

    if (depth != 0) {
        set_error("unterminated block");
        return false;
    }
    return true;
}

bool GServiceParser::Parser::skip_value() {
    if (current_token_.type == Token::LBrace) {
        return skip_block();
    }
    if (current_token_.type == Token::LBracket) {
        return skip_list();
    }
    if (is_value_token(current_token_.type)) {
        next_token();
        return true;
    }

    set_error("expected a value");
    return false;
}

bool GServiceParser::Parser::parse_deps(GService& service) {
    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    while (current_token_.type != Token::RBrace && current_token_.type != Token::EndOfFile) {
        if (current_token_.type != Token::Identifier) {
            set_error("expected dependency field");
            return false;
        }

        const std::string key = current_token_.value;
        next_token();
        if (!expect(Token::Equals, "'='")) {
            return false;
        }

        if (key == "after") {
            if (!parse_string_list(service.after)) {
                return false;
            }
        } else if (key == "wants") {
            if (!parse_string_list(service.wants)) {
                return false;
            }
        } else if (key == "requires") {
            if (!parse_string_list(service.required_services)) {
                return false;
            }
        } else if (!skip_value()) {
            return false;
        }
    }

    return expect(Token::RBrace, "'}'");
}

bool GServiceParser::Parser::parse_meta(GService& service) {
    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    while (current_token_.type != Token::RBrace && current_token_.type != Token::EndOfFile) {
        if (current_token_.type != Token::Identifier) {
            set_error("expected meta field");
            return false;
        }

        const std::string key = current_token_.value;
        next_token();
        if (key == "deps") {
            if (!parse_deps(service)) {
                return false;
            }
            continue;
        }

        if (!expect(Token::Equals, "'='")) {
            return false;
        }

        if (key == "description") {
            if (!parse_value(service.description)) {
                return false;
            }
        } else if (!skip_value()) {
            return false;
        }
    }

    return expect(Token::RBrace, "'}'");
}

bool GServiceParser::Parser::parse_commands(GService& service) {
    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    while (current_token_.type != Token::RBrace && current_token_.type != Token::EndOfFile) {
        if (current_token_.type != Token::Identifier) {
            set_error("expected process.commands field");
            return false;
        }

        const std::string key = current_token_.value;
        next_token();
        if (!expect(Token::Equals, "'='")) {
            return false;
        }

        if (key == "start_pre") {
            if (!parse_value(service.start_pre)) {
                return false;
            }
        } else if (key == "start") {
            if (!parse_value(service.start)) {
                return false;
            }
        } else if (key == "stop") {
            if (!parse_value(service.stop)) {
                return false;
            }
        } else if (!skip_value()) {
            return false;
        }
    }

    return expect(Token::RBrace, "'}'");
}

bool GServiceParser::Parser::parse_lifecycle(GService& service) {
    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    while (current_token_.type != Token::RBrace && current_token_.type != Token::EndOfFile) {
        if (current_token_.type != Token::Identifier) {
            set_error("expected process.lifecycle field");
            return false;
        }

        const std::string key = current_token_.value;
        next_token();
        if (!expect(Token::Equals, "'='")) {
            return false;
        }

        if (key == "restart_policy") {
            std::string value;
            if (!parse_value(value)) {
                return false;
            }
            if (value == "always") {
                service.restart_policy = RestartPolicy::Always;
            } else if (value == "on-failure") {
                service.restart_policy = RestartPolicy::OnFailure;
            } else if (value == "never" || value.empty()) {
                service.restart_policy = RestartPolicy::Never;
            } else {
                set_error("unsupported restart_policy '" + value + "'");
                return false;
            }
        } else if (key == "restart_delay") {
            if (!parse_duration_us(service.restart_delay_us)) {
                return false;
            }
        } else if (key == "stop_timeout") {
            if (!parse_duration_ms(service.stop_timeout_ms)) {
                return false;
            }
        } else if (!skip_value()) {
            return false;
        }
    }

    return expect(Token::RBrace, "'}'");
}

bool GServiceParser::Parser::parse_process(GService& service) {
    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    while (current_token_.type != Token::RBrace && current_token_.type != Token::EndOfFile) {
        if (current_token_.type != Token::Identifier) {
            set_error("expected process field");
            return false;
        }

        const std::string key = current_token_.value;
        next_token();

        if (key == "commands") {
            if (!parse_commands(service)) {
                return false;
            }
            continue;
        }
        if (key == "lifecycle") {
            if (!parse_lifecycle(service)) {
                return false;
            }
            continue;
        }

        if (!expect(Token::Equals, "'='")) {
            return false;
        }

        if (key == "type") {
            std::string type;
            if (!parse_value(type)) {
                return false;
            }
            if (type == "oneshot") {
                service.type = ServiceType::Oneshot;
            } else {
                service.type = ServiceType::Simple;
            }
        } else if (key == "user") {
            if (!parse_value(service.user)) {
                return false;
            }
        } else if (key == "group") {
            if (!parse_value(service.group)) {
                return false;
            }
        } else if (key == "work_dir") {
            if (!parse_value(service.work_dir)) {
                return false;
            }
        } else if (key == "failure_is_fatal") {
            if (!parse_bool_value(service.failure_is_fatal)) {
                return false;
            }
        } else if (!skip_value()) {
            return false;
        }
    }

    return expect(Token::RBrace, "'}'");
}

bool GServiceParser::Parser::parse_vars(GService& service) {
    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    while (current_token_.type != Token::RBrace && current_token_.type != Token::EndOfFile) {
        if (current_token_.type != Token::Identifier) {
            set_error("expected env.vars field");
            return false;
        }

        const std::string key = current_token_.value;
        next_token();
        if (!expect(Token::Equals, "'='")) {
            return false;
        }

        std::string value;
        if (!parse_value(value)) {
            return false;
        }

        bool replaced = false;
        for (auto& item : service.env_vars) {
            if (item.name == key) {
                item.value = std::move(value);
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            service.env_vars.push_back({key, std::move(value)});
        }
    }

    return expect(Token::RBrace, "'}'");
}

bool GServiceParser::Parser::parse_env(GService& service) {
    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    while (current_token_.type != Token::RBrace && current_token_.type != Token::EndOfFile) {
        if (current_token_.type != Token::Identifier) {
            set_error("expected env field");
            return false;
        }

        const std::string key = current_token_.value;
        next_token();
        if (key == "vars") {
            if (!parse_vars(service)) {
                return false;
            }
            continue;
        }

        if (!expect(Token::Equals, "'='")) {
            return false;
        }

        if (key == "load_file") {
            if (!parse_value(service.env_file)) {
                return false;
            }
        } else if (!skip_value()) {
            return false;
        }
    }

    return expect(Token::RBrace, "'}'");
}

bool GServiceParser::Parser::parse_security(GService& service) {
    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    while (current_token_.type != Token::RBrace && current_token_.type != Token::EndOfFile) {
        if (current_token_.type != Token::Identifier) {
            set_error("expected security field");
            return false;
        }

        const std::string key = current_token_.value;
        next_token();
        if (!expect(Token::Equals, "'='")) {
            return false;
        }

        if (key == "no_new_privileges") {
            if (!parse_bool_value(service.no_new_privileges)) {
                return false;
            }
        } else if (!skip_value()) {
            return false;
        }
    }

    return expect(Token::RBrace, "'}'");
}

bool GServiceParser::Parser::parse_install() {
    return skip_block();
}

bool GServiceParser::Parser::parse_resources() {
    return skip_block();
}

bool GServiceParser::Parser::parse_service(GService& service) {
    if (!expect_identifier("service")) {
        return false;
    }

    if (current_token_.type != Token::String) {
        set_error("expected quoted service name");
        return false;
    }
    service.name = current_token_.value;
    next_token();

    if (!expect(Token::LBrace, "'{'")) {
        return false;
    }

    while (current_token_.type != Token::RBrace && current_token_.type != Token::EndOfFile) {
        if (current_token_.type != Token::Identifier) {
            set_error("expected service block name");
            return false;
        }

        const std::string key = current_token_.value;
        next_token();

        if (key == "meta") {
            if (!parse_meta(service)) {
                return false;
            }
        } else if (key == "process") {
            if (!parse_process(service)) {
                return false;
            }
        } else if (key == "env") {
            if (!parse_env(service)) {
                return false;
            }
        } else if (key == "security") {
            if (!parse_security(service)) {
                return false;
            }
        } else if (key == "install") {
            if (!parse_install()) {
                return false;
            }
        } else if (key == "resources") {
            if (!parse_resources()) {
                return false;
            }
        } else if (!skip_value()) {
            return false;
        }
    }

    if (!expect(Token::RBrace, "'}'")) {
        return false;
    }

    if (service.name.empty()) {
        set_error("service name must not be empty");
        return false;
    }
    if (service.start.empty()) {
        set_error("service is missing process.commands.start");
        return false;
    }
    return true;
}

std::optional<GService> GServiceParser::Parser::parse() {
    GService service;
    if (!parse_service(service)) {
        return std::nullopt;
    }
    if (current_token_.type != Token::EndOfFile) {
        set_error("unexpected trailing content after service definition");
        return std::nullopt;
    }
    return service;
}

std::optional<GService> GServiceParser::parse_file(const std::string& filename, std::string* error) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        if (error) {
            *error = "unable to open file";
        }
        return std::nullopt;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    return parse_string(buffer.str(), error);
}

std::optional<GService> GServiceParser::parse_string(const std::string& content, std::string* error) {
    Lexer lexer(content);
    Parser parser(lexer);
    std::optional<GService> service = parser.parse();
    if (!service && error) {
        *error = parser.error_message();
    }
    return service;
}

} // namespace ginit
