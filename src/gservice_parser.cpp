#include "gservice_parser.hpp"
#include <fstream>
#include <sstream>
#include <cctype>
#include <stdexcept>
#include <iostream>

namespace ginit {

GServiceParser::Lexer::Lexer(const std::string& input) : input(input) {}

void GServiceParser::Lexer::skip_whitespace_and_comments() {
    while (pos < input.length()) {
        if (std::isspace(input[pos])) {
            pos++;
        } else if (pos + 1 < input.length() && input[pos] == '/' && input[pos+1] == '/') {
            // Skip single line comment
            pos += 2;
            while (pos < input.length() && input[pos] != '\n') {
                pos++;
            }
        } else {
            break;
        }
    }
}

GServiceParser::Token GServiceParser::Lexer::next_token() {
    skip_whitespace_and_comments();

    if (pos >= input.length()) {
        return {Token::END_OF_FILE, ""};
    }

    char c = input[pos];

    if (std::isalpha(c) || c == '_') {
        std::string value;
        while (pos < input.length() && (std::isalnum(input[pos]) || input[pos] == '_')) {
            value += input[pos++];
        }
        return {Token::IDENTIFIER, value};
    }

    if (std::isdigit(c)) {
        std::string value;
        while (pos < input.length() && (std::isdigit(input[pos]) || input[pos] == '.')) {
            value += input[pos++];
        }
        return {Token::NUMBER, value};
    }

    if (c == '"') {
        std::string value;
        pos++; // skip "
        while (pos < input.length() && input[pos] != '"') {
            if (input[pos] == '\\' && pos + 1 < input.length()) {
                pos++;
                switch (input[pos]) {
                    case 'n': value += '\n'; break;
                    case 'r': value += '\r'; break;
                    case 't': value += '\t'; break;
                    default: value += input[pos]; break;
                }
            } else {
                value += input[pos];
            }
            pos++;
        }
        if (pos < input.length()) pos++; // skip "
        return {Token::STRING, value};
    }

    pos++;
    switch (c) {
        case '{': return {Token::LBRACE, "{"};
        case '}': return {Token::RBRACE, "}"};
        case '[': return {Token::LBRACKET, "["};
        case ']': return {Token::RBRACKET, "]"};
        case '=': return {Token::EQUALS, "="};
        case ',': return {Token::COMMA, ","};
    }

    return {Token::ERROR, std::string(1, c)};
}

GServiceParser::Parser::Parser(Lexer& lexer) : lexer(lexer) {
    next_token();
}

void GServiceParser::Parser::next_token() {
    current_token = lexer.next_token();
}

bool GServiceParser::Parser::match(Token::Type type) {
    if (current_token.type == type) {
        next_token();
        return true;
    }
    return false;
}

bool GServiceParser::Parser::expect(Token::Type type) {
    if (current_token.type == type) {
        next_token();
        return true;
    }
    // In a real parser we'd throw a more descriptive error
    std::cerr << "Expected token type " << type << " but got " << current_token.type << " with value " << current_token.value << std::endl;
    return false;
}

std::string GServiceParser::Parser::parse_value() {
    if (current_token.type == Token::STRING || current_token.type == Token::NUMBER || current_token.type == Token::IDENTIFIER) {
        std::string val = current_token.value;
        next_token();
        return val;
    }
    return "";
}

std::vector<std::string> GServiceParser::Parser::parse_string_list() {
    std::vector<std::string> list;
    if (!expect(Token::LBRACKET)) return list;
    
    while (current_token.type != Token::RBRACKET && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::STRING) {
            list.push_back(current_token.value);
            next_token();
        } else {
            next_token();
        }
        if (current_token.type == Token::COMMA) {
            next_token();
        }
    }
    expect(Token::RBRACKET);
    return list;
}

void GServiceParser::Parser::parse_deps(Meta::Deps& deps) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            expect(Token::EQUALS);
            if (key == "after") deps.after = parse_string_list();
            else if (key == "wants") deps.wants = parse_string_list();
            else if (key == "requires") deps.requires = parse_string_list();
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

void GServiceParser::Parser::parse_meta(Meta& meta) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            if (key == "deps") {
                parse_deps(meta.deps);
            } else {
                expect(Token::EQUALS);
                if (key == "description") meta.description = parse_value();
                else if (key == "docs") meta.docs = parse_value();
            }
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

void GServiceParser::Parser::parse_commands(Process::Commands& commands) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            expect(Token::EQUALS);
            if (key == "start_pre") commands.start_pre = parse_value();
            else if (key == "start") commands.start = parse_value();
            else if (key == "reload") commands.reload = parse_value();
            else if (key == "stop") commands.stop = parse_value();
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

void GServiceParser::Parser::parse_lifecycle(Process::Lifecycle& lifecycle) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            expect(Token::EQUALS);
            if (key == "restart_policy") lifecycle.restart_policy = parse_value();
            else if (key == "restart_delay") lifecycle.restart_delay = parse_value();
            else if (key == "stop_timeout") lifecycle.stop_timeout = parse_value();
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

void GServiceParser::Parser::parse_process(Process& process) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            if (key == "commands") {
                parse_commands(process.commands);
            } else if (key == "lifecycle") {
                parse_lifecycle(process.lifecycle);
            } else {
                expect(Token::EQUALS);
                if (key == "type") process.type = parse_value();
                else if (key == "user") process.user = parse_value();
                else if (key == "group") process.group = parse_value();
                else if (key == "work_dir") process.work_dir = parse_value();
            }
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

void GServiceParser::Parser::parse_vars(std::map<std::string, std::string>& vars) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            expect(Token::EQUALS);
            vars[key] = parse_value();
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

void GServiceParser::Parser::parse_env(Env& env) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            expect(Token::EQUALS);
            if (key == "load_file") env.load_file = parse_value();
            else if (key == "vars") parse_vars(env.vars);
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

// Fixed security parser to handle lists
void GServiceParser::Parser::parse_security(Security& security) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            expect(Token::EQUALS);
            if (key == "rw_paths") {
                security.rw_paths = parse_string_list();
            } else {
                std::string val = parse_value();
                if (key == "no_new_privileges") security.no_new_privileges = (val == "true");
                else if (key == "protect_system") security.protect_system = val;
                else if (key == "protect_home") security.protect_home = (val == "true");
                else if (key == "private_tmp") security.private_tmp = (val == "true");
            }
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

void GServiceParser::Parser::parse_resources(Resources& resources) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            expect(Token::EQUALS);
            if (key == "ulimit_nofile") resources.ulimit_nofile = std::stoi(parse_value());
            else if (key == "memory_max") resources.memory_max = parse_value();
            else if (key == "cpu_quota") resources.cpu_quota = parse_value();
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

void GServiceParser::Parser::parse_install(Install& install) {
    expect(Token::LBRACE);
    while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
        if (current_token.type == Token::IDENTIFIER) {
            std::string key = current_token.value;
            next_token();
            expect(Token::EQUALS);
            if (key == "wanted_by") install.wanted_by = parse_string_list();
            else if (key == "alias") install.alias = parse_value();
        } else {
            next_token();
        }
    }
    expect(Token::RBRACE);
}

std::unique_ptr<GService> GServiceParser::Parser::parse() {
    auto service = std::make_unique<GService>();
    if (current_token.type == Token::IDENTIFIER && current_token.value == "service") {
        next_token();
        if (current_token.type == Token::STRING) {
            service->name = current_token.value;
            next_token();
        }
        expect(Token::LBRACE);
        while (current_token.type != Token::RBRACE && current_token.type != Token::END_OF_FILE) {
            if (current_token.type == Token::IDENTIFIER) {
                std::string key = current_token.value;
                next_token();
                if (key == "meta") parse_meta(service->meta);
                else if (key == "process") parse_process(service->process);
                else if (key == "env") parse_env(service->env);
                else if (key == "security") parse_security(service->security);
                else if (key == "resources") parse_resources(service->resources);
                else if (key == "install") parse_install(service->install);
                else {
                    // Unknown block, skip it
                    if (current_token.type == Token::LBRACE) {
                        int depth = 1;
                        next_token();
                        while (depth > 0 && current_token.type != Token::END_OF_FILE) {
                            if (current_token.type == Token::LBRACE) depth++;
                            if (current_token.type == Token::RBRACE) depth--;
                            next_token();
                        }
                    } else if (match(Token::EQUALS)) {
                        parse_value();
                    }
                }
            } else {
                next_token();
            }
        }
        expect(Token::RBRACE);
    }
    return service;
}

std::unique_ptr<GService> GServiceParser::parse_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return nullptr;
    std::stringstream buffer;
    buffer << file.rdbuf();
    return parse_string(buffer.str());
}

std::unique_ptr<GService> GServiceParser::parse_string(const std::string& content) {
    Lexer lexer(content);
    Parser parser(lexer);
    return parser.parse();
}

} // namespace ginit
