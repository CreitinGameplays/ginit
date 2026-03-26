#include "network.h"
#include "signals.h"
#include "debug.h"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/route.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>
#include <cstdlib> // for atoi
#include <chrono>
#include <iomanip>
#include <thread>
#include <future>
#include <mutex>
#include <atomic>
#include <cmath>
#include <numeric>
#include <unordered_map>

// QEMU Default Network Settings
#define MY_IP "10.0.2.15"
#define GATEWAY "10.0.2.2"
#define NETMASK "255.255.255.0"
#define DNS_SERVER "10.0.2.3" // QEMU User Network DNS

#include <ifaddrs.h>

std::string GetFirstInterface() {
    struct ifaddrs *ifaddr, *ifa;
    std::string name = "eth0"; // Default fallback

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return name;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        std::string ifa_name = ifa->ifa_name;
        // Skip loopback and non-IP interfaces (we just want names)
        if (ifa_name != "lo") {
            name = ifa_name;
            break; 
        }
    }

    freeifaddrs(ifaddr);
    return name;
}

int ConfigureNetwork() {
    std::string iface = GetFirstInterface();
    std::cout << "[NET] Using interface: " << iface << std::endl;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("[NET] socket");
        return 1;
    }

    // 0. Setup Loopback (lo)
    struct ifreq ifr_lo;
    memset(&ifr_lo, 0, sizeof(ifr_lo));
    strncpy(ifr_lo.ifr_name, "lo", IFNAMSIZ);
    // Get current flags
    if (ioctl(sock, SIOCGIFFLAGS, &ifr_lo) >= 0) {
        ifr_lo.ifr_flags |= (IFF_UP | IFF_LOOPBACK | IFF_RUNNING);
        if (ioctl(sock, SIOCSIFFLAGS, &ifr_lo) < 0) {
             perror("[NET] Failed to bring up lo");
        }
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);

    // 1. Set IP Address
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, MY_IP, &addr->sin_addr);
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        perror(("[NET] Failed to set IP on " + iface).c_str());
        close(sock); return 1;
    }

    // 2. Bring Interface UP
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror(("[NET] Failed to get flags for " + iface).c_str());
        close(sock); return 1;
    }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror(("[NET] Failed to bring up " + iface).c_str());
        close(sock); return 1;
    }

    // 3. Set Default Gateway (Legacy IOCTL method)
    struct rtentry route;
    memset(&route, 0, sizeof(route));
    
    struct sockaddr_in* dst = (struct sockaddr_in*)&route.rt_dst;
    dst->sin_family = AF_INET;
    dst->sin_addr.s_addr = INADDR_ANY;

    struct sockaddr_in* mask = (struct sockaddr_in*)&route.rt_genmask;
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = INADDR_ANY;

    struct sockaddr_in* gw = (struct sockaddr_in*)&route.rt_gateway;
    gw->sin_family = AF_INET;
    inet_pton(AF_INET, GATEWAY, &gw->sin_addr);

    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_dev = (char*)iface.c_str(); // Use detected interface

    if (ioctl(sock, SIOCADDRT, &route) < 0) {
        if (errno != EEXIST) {
            // LOG_DEBUG("Failed to set gateway: " << strerror(errno));
        }
    }

    close(sock);

    // 4. Generate /etc/resolv.conf for system tools (pip, wget, etc)
    std::ofstream resolv("/etc/resolv.conf");
    if (resolv) {
        resolv << "nameserver " << DNS_SERVER << "\n"; // 10.0.2.3
        resolv << "nameserver 8.8.8.8\n"; // Fallback
        resolv << "options timeout:2 attempts:1\n";
        resolv.close();
        std::cout << "[NET] Generated /etc/resolv.conf" << std::endl;
    }

    // 5. Generate /etc/hosts
    std::ofstream hosts("/etc/hosts");
    if (hosts) {
        hosts << "127.0.0.1\tlocalhost\n";
        hosts << "127.0.1.1\tgeminios-pc\n";
        hosts << MY_IP << "\tgeminios-pc\n";
        hosts << "::1\tlocalhost ip6-localhost ip6-loopback\n";
        hosts.close();
        std::cout << "[NET] Generated /etc/hosts" << std::endl;
    }

    std::cout << "[NET] Network Configured: " << MY_IP << " (DNS: " << DNS_SERVER << ")" << std::endl;
    return 0;
}

// Minimal DNS Resolver (UDP to 8.8.8.8)
std::string ResolveDNS(const std::string& host) {
    // Return immediately if it's already an IP
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, host.c_str(), &(sa.sin_addr)) != 0) return host;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0) return "";

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, DNS_SERVER, &dest.sin_addr);

    // DNS Query Construction (Header + QNAME + QTYPE + QCLASS)
    unsigned char buf[512];
    memset(buf, 0, 512);
    
    // Header: ID=0x1234, Flags=0x0100 (Standard Query), QDCOUNT=1
    buf[0] = 0x12; buf[1] = 0x34; buf[2] = 0x01; buf[5] = 0x01;

    // QNAME: simple www.example.com -> 3www7example3com0
    int pos = 12;
    int start = 0;
    for(int i=0; i <= (int)host.length(); i++) {
        if(i == (int)host.length() || host[i] == '.') {
            buf[pos++] = i - start;
            for(int j=start; j<i; j++) buf[pos++] = host[j];
            start = i + 1;
        }
    }
    buf[pos++] = 0; // Null terminator
    buf[pos++] = 0x00; buf[pos++] = 0x01; // QTYPE=A
    buf[pos++] = 0x00; buf[pos++] = 0x01; // QCLASS=IN

    struct timeval tv = {4, 0}; // 4 second timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    LOG_DEBUG("Sending DNS query to " << DNS_SERVER << "...");
    if (sendto(sock, buf, pos, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("[ERR] DNS sendto failed");
        close(sock); return "";
    }
    
    int len = recv(sock, buf, 512, 0);
    if (len < 0) {
        if (errno == EINTR || g_stop_sig) {
            // Interrupted by Ctrl+C
        } else {
            perror("[ERR] DNS recv failed (timeout?)");
        }
    } else {
        LOG_DEBUG("DNS response: " << len << " bytes");
        // LOG_HEX("HEX", buf, len);
        
        if ((buf[3] & 0x0F) != 0) printf("[ERR] DNS RCODE: %d\n", buf[3] & 0x0F);
    }
    close(sock);
    if(len < 0) return "";

    // Parse Response (Skip Header, Query, find Answer)
    // Simplified: Find the bytes for Type A (00 01) inside answer section
    // This is a hacky educational parser.
    if(len > 12) { 
        // Scan entire packet (skipping 12 byte header) for 00 04 (IPv4 Len)
        // Limit loop to len - 6 to ensure we have 6 bytes (00 04 IP IP IP IP)
        for(int i=12; i <= len - 6; i++) {
            // Look for Data Length = 4 (IPv4)
            if(buf[i] == 0x00 && buf[i+1] == 0x04) {
                char ip[INET_ADDRSTRLEN];
                sprintf(ip, "%d.%d.%d.%d", buf[i+2], buf[i+3], buf[i+4], buf[i+5]);
                return std::string(ip);
            }
        }
    }
    return "";
}

// Helper: Base64 Encoding for Basic Auth
std::string base64_encode(const std::string& in) {
    std::string out;
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// Helper to format speed
std::string format_speed(double bytes_per_sec) {
    if (bytes_per_sec > 1024 * 1024 * 1024) return std::to_string((int)(bytes_per_sec / (1024 * 1024 * 1024))) + " GBps";
    if (bytes_per_sec > 1024 * 1024) return std::to_string((int)(bytes_per_sec / (1024 * 1024))) + " MBps";
    if (bytes_per_sec > 1024) return std::to_string((int)(bytes_per_sec / 1024)) + " KBps";
    return std::to_string((int)bytes_per_sec) + " Bps";
}

std::string trim_copy(const std::string& value) {
    size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

void set_error(std::string* error_out, const std::string& message) {
    if (error_out) *error_out = message;
}

namespace {
constexpr size_t kTransferBufferSize = 64 * 1024;
constexpr int kSocketBufferBytes = 1 << 20;
constexpr long kParallelDownloadThresholdBytes = 5L * 1024L * 1024L;

struct RemoteFileInfo {
    long content_length = -1;
    bool accepts_ranges = false;
    std::string etag;
    std::string last_modified;
};

struct PersistentHttpConnection {
    int sock = -1;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
};

void close_persistent_http_connection(PersistentHttpConnection& conn) {
    if (conn.ssl) {
        SSL_shutdown(conn.ssl);
        SSL_free(conn.ssl);
        conn.ssl = nullptr;
    }
    if (conn.ctx) {
        SSL_CTX_free(conn.ctx);
        conn.ctx = nullptr;
    }
    if (conn.sock >= 0) {
        close(conn.sock);
        conn.sock = -1;
    }
}

struct PersistentHttpConnectionPool {
    std::unordered_map<std::string, PersistentHttpConnection> connections;

    ~PersistentHttpConnectionPool() {
        for (auto& entry : connections) {
            close_persistent_http_connection(entry.second);
        }
    }
};

std::mutex g_remote_file_info_mutex;
std::unordered_map<std::string, RemoteFileInfo> g_remote_file_info_cache;
thread_local PersistentHttpConnectionPool g_persistent_http_connection_pool;

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    return value;
}

bool host_matches_no_proxy_token(const std::string& host, std::string token) {
    token = trim_copy(lower_copy(token));
    if (token.empty()) return false;
    if (token == "*") return true;

    if (token.front() == '.') {
        return host.size() > token.size() - 1 &&
            host.compare(host.size() - (token.size() - 1), token.size() - 1, token.substr(1)) == 0;
    }

    if (host == token) return true;
    return host.size() > token.size() &&
        host.compare(host.size() - token.size(), token.size(), token) == 0 &&
        host[host.size() - token.size() - 1] == '.';
}

bool should_bypass_proxy_for_host(const std::string& host) {
    std::string lower_host = lower_copy(host);
    if (lower_host == "localhost" || lower_host == "127.0.0.1" || lower_host == "::1") {
        return true;
    }

    const char* no_proxy = getenv("no_proxy");
    if (!no_proxy || !*no_proxy) no_proxy = getenv("NO_PROXY");
    if (!no_proxy || !*no_proxy) return false;

    std::stringstream ss(no_proxy);
    std::string token;
    while (std::getline(ss, token, ',')) {
        if (host_matches_no_proxy_token(lower_host, token)) {
            return true;
        }
    }

    return false;
}

int parse_http_status_code(const std::string& headers) {
    size_t first_line_end = headers.find("\r\n");
    std::string status_line = first_line_end == std::string::npos
        ? headers
        : headers.substr(0, first_line_end);

    size_t first_space = status_line.find(' ');
    if (first_space == std::string::npos) return 0;
    size_t code_start = status_line.find_first_not_of(' ', first_space);
    if (code_start == std::string::npos) return 0;
    size_t code_end = status_line.find_first_not_of("0123456789", code_start);
    std::string code_text = status_line.substr(code_start, code_end - code_start);
    return std::atoi(code_text.c_str());
}

std::string parse_header_value(
    const std::string& headers,
    const std::string& lower_headers,
    const std::string& header_name
) {
    size_t pos = lower_headers.find(header_name);
    if (pos == std::string::npos) return "";

    size_t start = pos + header_name.size();
    size_t end = lower_headers.find("\r\n", start);
    if (end == std::string::npos) end = lower_headers.size();
    return trim_copy(headers.substr(start, end - start));
}

long parse_content_length_header(const std::string& headers, const std::string& lower_headers) {
    std::string value = parse_header_value(headers, lower_headers, "content-length: ");
    if (value.empty()) return -1;
    return std::atol(value.c_str());
}

bool parse_accept_ranges_header(const std::string& lower_headers) {
    size_t pos = lower_headers.find("accept-ranges: ");
    if (pos == std::string::npos) return false;

    size_t end = lower_headers.find("\r\n", pos);
    if (end == std::string::npos) end = lower_headers.size();
    std::string value = trim_copy(lower_headers.substr(pos + 15, end - (pos + 15)));
    return value.find("bytes") != std::string::npos;
}

bool probe_remote_file(const std::string& url, RemoteFileInfo* info) {
    if (!info) return false;

    {
        std::lock_guard<std::mutex> lock(g_remote_file_info_mutex);
        auto it = g_remote_file_info_cache.find(url);
        if (it != g_remote_file_info_cache.end()) {
            *info = it->second;
            return true;
        }
    }

    HttpOptions opts;
    opts.method = "HEAD";
    opts.include_headers = true;
    opts.follow_location = true;
    opts.allow_connection_reuse = true;
    opts.verbose = false;

    std::stringstream ss;
    if (!HttpRequest(url, ss, opts)) return false;

    std::string response = ss.str();
    std::string lower_response = lower_copy(response);

    int status_code = parse_http_status_code(response);
    if (status_code < 200 || status_code >= 300) return false;

    RemoteFileInfo parsed;
    parsed.content_length = parse_content_length_header(response, lower_response);
    parsed.accepts_ranges = parse_accept_ranges_header(lower_response);
    parsed.etag = parse_header_value(response, lower_response, "etag: ");
    parsed.last_modified = parse_header_value(response, lower_response, "last-modified: ");

    {
        std::lock_guard<std::mutex> lock(g_remote_file_info_mutex);
        g_remote_file_info_cache[url] = parsed;
    }

    *info = parsed;
    return true;
}

void configure_transfer_socket(int sock) {
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));
}

bool write_all(int sock, const char* data, size_t len) {
    size_t total_written = 0;
    while (total_written < len) {
        ssize_t written = write(sock, data + total_written, len - total_written);
        if (written < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (written == 0) return false;
        total_written += static_cast<size_t>(written);
    }
    return true;
}

bool ssl_write_all(SSL* ssl, const char* data, size_t len) {
    size_t total_written = 0;
    while (total_written < len) {
        int written = SSL_write(ssl, data + total_written, static_cast<int>(len - total_written));
        if (written <= 0) {
            int ssl_err = SSL_get_error(ssl, written);
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) continue;
            return false;
        }
        total_written += static_cast<size_t>(written);
    }
    return true;
}

bool has_partial_download(const std::string& temp_path) {
    struct stat st;
    return stat(temp_path.c_str(), &st) == 0 && st.st_size > 0;
}

int choose_parallel_thread_count(long content_length) {
    if (content_length >= 512L * 1024L * 1024L) return 8;
    if (content_length >= 128L * 1024L * 1024L) return 6;
    if (content_length >= 32L * 1024L * 1024L) return 4;
    return 2;
}

std::string build_http_connection_pool_key(
    bool use_ssl,
    const std::string& host,
    int port,
    const std::string& connect_host,
    int connect_port,
    const std::string& proxy,
    const std::string& auth
) {
    std::ostringstream out;
    out << (use_ssl ? "https" : "http")
        << "|" << host << ":" << port
        << "|" << connect_host << ":" << connect_port
        << "|" << proxy
        << "|" << auth;
    return out.str();
}

bool open_http_transport_connection(
    const std::string& connect_host,
    int connect_port,
    const std::string& host,
    int port,
    bool use_ssl,
    const std::string& proxy_str,
    const std::string& proxy_auth_header,
    bool verbose,
    PersistentHttpConnection& conn,
    std::string* error_out
) {
    close_persistent_http_connection(conn);

    std::string ip = ResolveDNS(connect_host);
    if (ip.empty()) {
        if (verbose) std::cerr << "[ERR] Could not resolve: " << connect_host << std::endl;
        set_error(error_out, "could not resolve " + connect_host);
        return false;
    }
    if (verbose) std::cerr << "[NET] Connecting to IP: " << ip << std::endl;

    if (g_stop_sig) {
        set_error(error_out, "interrupted by signal");
        return false;
    }

    conn.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (conn.sock < 0) {
        if (verbose) perror("[ERR] Socket creation failed");
        set_error(error_out, std::string("socket creation failed: ") + strerror(errno));
        return false;
    }
    configure_transfer_socket(conn.sock);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(connect_port);
    inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr);

    if (connect(conn.sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        if (verbose) perror("[ERR] Connection failed");
        set_error(error_out, std::string("connection failed: ") + strerror(errno));
        close_persistent_http_connection(conn);
        return false;
    }

    if (!proxy_str.empty() && use_ssl) {
        std::string connect_req = "CONNECT " + host + ":" + std::to_string(port) + " HTTP/1.1\r\n";
        connect_req += "Host: " + host + ":" + std::to_string(port) + "\r\n";
        connect_req += proxy_auth_header;
        connect_req += "\r\n";

        if (verbose) std::cerr << "[NET] Sending Proxy CONNECT..." << std::endl;
        if (!write_all(conn.sock, connect_req.c_str(), connect_req.length())) {
            set_error(error_out, std::string("failed to send proxy CONNECT request: ") + strerror(errno));
            close_persistent_http_connection(conn);
            return false;
        }

        char tmp[1024];
        int len = read(conn.sock, tmp, sizeof(tmp) - 1);
        if (len <= 0) {
            set_error(error_out, "proxy CONNECT failed");
            close_persistent_http_connection(conn);
            return false;
        }
        tmp[len] = 0;
        if (std::string(tmp).find("200") == std::string::npos) {
            if (verbose) std::cerr << "[ERR] Proxy CONNECT failed: " << tmp << std::endl;
            set_error(error_out, "proxy CONNECT failed");
            close_persistent_http_connection(conn);
            return false;
        }
    }

    if (use_ssl) {
        SSL_library_init();
        conn.ctx = SSL_CTX_new(TLS_client_method());
        if (!conn.ctx) {
            if (verbose) std::cerr << "[ERR] SSL Context failed" << std::endl;
            set_error(error_out, "failed to initialize SSL context");
            close_persistent_http_connection(conn);
            return false;
        }
        SSL_CTX_set_verify(conn.ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_mode(conn.ctx, SSL_MODE_AUTO_RETRY | SSL_MODE_RELEASE_BUFFERS);

        conn.ssl = SSL_new(conn.ctx);
        SSL_set_tlsext_host_name(conn.ssl, host.c_str());
        SSL_set_fd(conn.ssl, conn.sock);

        if (SSL_connect(conn.ssl) <= 0) {
            if (verbose) ERR_print_errors_fp(stderr);
            set_error(error_out, "TLS handshake failed");
            close_persistent_http_connection(conn);
            return false;
        }
    }

    return true;
}
}

bool HttpRequestInternal(const std::string& url_in, std::ostream& out, const HttpOptions& opts, std::string* error_out);

bool HttpRequest(const std::string& url, std::ostream& out, const HttpOptions& opts, std::string* error_out) {
    int attempts = 0;
    int max_attempts = opts.retry_count + 1;
    std::string last_error;
    
    while (attempts < max_attempts) {
        if (g_stop_sig) return false;
        
        if (attempts > 0) {
            if (opts.verbose) std::cerr << "[NET] Retry attempt " << attempts << " for " << url << "..." << std::endl;
            sleep(opts.retry_delay);
        }
        
        // We need a way to clear the output stream if it's a file, 
        // but since it's an ostream, we can't easily "reset" it unless it's a file we can seek.
        // For simplicity, we assume the internal logic handles it or it's okay.
        // Actually, if it's an ofstream, we might want to truncate it.
        // But ostream doesn't have truncate.
        
        if (HttpRequestInternal(url, out, opts, &last_error)) {
            set_error(error_out, "");
            return true;
        }
        
        attempts++;
        if (g_stop_sig) return false;
    }
    
    set_error(error_out, last_error);
    return false;
}

bool HttpRequestInternal(const std::string& url_in, std::ostream& out, const HttpOptions& opts, std::string* error_out) {
    if (opts.max_redirects < 0) {
        if (opts.verbose) std::cerr << "[NET] Max redirects reached" << std::endl;
        set_error(error_out, "too many redirects");
        return false;
    }

    // 1. Parse Protocol and URL
    std::string protocol = "http";
    std::string url_part = url_in;

    size_t sep = url_in.find("://");
    if (sep != std::string::npos) {
        protocol = url_in.substr(0, sep);
        url_part = url_in.substr(sep + 3);
    } else {
        if (opts.verbose) std::cerr << "[NET] No protocol specified, defaulting to HTTP" << std::endl;
    }

    // 2. Parse Host and Path
    std::string authority;
    std::string host;
    std::string path;

    size_t slash_pos = url_part.find('/');
    if (slash_pos != std::string::npos) {
        authority = url_part.substr(0, slash_pos);
        path = url_part.substr(slash_pos);
    } else {
        authority = url_part;
        path = "/";
    }

    // 3. Determine Port and SSL mode
    bool use_ssl = false;
    int port = 80;

    if (protocol == "https") {
        use_ssl = true;
        port = 443;
    } else if (protocol != "http") {
        if (opts.verbose) std::cerr << "[ERR] Unsupported protocol: " << protocol << std::endl;
        set_error(error_out, "unsupported protocol: " + protocol);
        return false;
    }

    std::string host_header = authority;
    if (!authority.empty() && authority.front() == '[') {
        size_t closing = authority.find(']');
        if (closing == std::string::npos) {
            set_error(error_out, "invalid IPv6 host syntax");
            return false;
        }

        host = authority.substr(1, closing - 1);
        if (closing + 1 < authority.size()) {
            if (authority[closing + 1] != ':') {
                set_error(error_out, "invalid IPv6 host syntax");
                return false;
            }
            std::string port_text = authority.substr(closing + 2);
            int parsed_port = std::atoi(port_text.c_str());
            if (parsed_port <= 0) {
                set_error(error_out, "invalid port in URL");
                return false;
            }
            port = parsed_port;
        }
    } else {
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) {
            std::string port_text = authority.substr(colon + 1);
            int parsed_port = std::atoi(port_text.c_str());
            if (parsed_port <= 0) {
                set_error(error_out, "invalid port in URL");
                return false;
            }
            host = authority.substr(0, colon);
            port = parsed_port;
        } else {
            host = authority;
        }
    }

    if (host.empty()) {
        set_error(error_out, "missing host in URL");
        return false;
    }

    if (opts.verbose) std::cerr << "[NET] Target: " << host << " (" << protocol << ":" << port << ")" << std::endl;

    // 4. Proxy / DNS Setup
    std::string connect_host = host;
    int connect_port = port;
    std::string proxy_auth_header;
    std::string proxy_str = opts.proxy;

    // Auto-detect proxy if not manually specified
    if (proxy_str.empty()) {
        // 1. Environment Variables
        const char* env_proxy = nullptr;
        if (use_ssl) {
            env_proxy = getenv("https_proxy");
            if (!env_proxy) env_proxy = getenv("HTTPS_PROXY");
        } else {
            env_proxy = getenv("http_proxy");
            if (!env_proxy) env_proxy = getenv("HTTP_PROXY");
        }
        if (env_proxy) proxy_str = env_proxy;

        // 2. Global Config (/etc/geminios/proxy.conf)
        if (proxy_str.empty()) {
            std::ifstream pf("/etc/geminios/proxy.conf");
            if (pf) {
                std::string line;
                std::string key_target = use_ssl ? "HTTPS_PROXY" : "HTTP_PROXY";
                while(std::getline(pf, line)) {
                    // Simple parsing KEY=VALUE
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string key = line.substr(0, eq);
                        std::string val = line.substr(eq + 1);
                        
                        // Case-insensitive comparison for key
                        std::string key_upper = key;
                        std::transform(key_upper.begin(), key_upper.end(), key_upper.begin(), ::toupper);
                        
                        if (key_upper == key_target) {
                            proxy_str = val;
                            break;
                        }
                    }
                }
            }
        }
    }

    if (!proxy_str.empty()) {
        if (should_bypass_proxy_for_host(host)) {
            if (opts.verbose) std::cerr << "[NET] Bypassing proxy for " << host << std::endl;
            proxy_str.clear();
        }
    }

    if (!proxy_str.empty()) {
        std::string p_host_port = proxy_str;
        // Handle http:// prefix in proxy string if present
        if (p_host_port.find("://") != std::string::npos) {
            p_host_port = p_host_port.substr(p_host_port.find("://") + 3);
        }

        size_t at = p_host_port.find('@');
        if (at != std::string::npos) {
            std::string p_auth = p_host_port.substr(0, at);
            p_host_port = p_host_port.substr(at + 1);
            proxy_auth_header = "Proxy-Authorization: Basic " + base64_encode(p_auth) + "\r\n";
        }
        size_t c = p_host_port.find(':');
        if (c != std::string::npos) {
            connect_host = p_host_port.substr(0, c);
            connect_port = std::atoi(p_host_port.substr(c + 1).c_str());
        } else {
            connect_host = p_host_port;
            connect_port = 8080; 
        }
        if (opts.verbose) std::cerr << "[NET] Using Proxy: " << connect_host << ":" << connect_port << std::endl;
    }

    const bool allow_connection_reuse = opts.allow_connection_reuse &&
        opts.data.empty() &&
        (opts.method == "GET" || opts.method == "HEAD");

    std::string pool_key;
    PersistentHttpConnection transient_conn;
    PersistentHttpConnection* active_conn = &transient_conn;
    if (allow_connection_reuse) {
        pool_key = build_http_connection_pool_key(
            use_ssl,
            host,
            port,
            connect_host,
            connect_port,
            proxy_str,
            opts.auth
        );
        active_conn = &g_persistent_http_connection_pool.connections[pool_key];
    }

    bool reused_existing_connection = active_conn->sock >= 0;
    if (!reused_existing_connection) {
        if (!open_http_transport_connection(
                connect_host,
                connect_port,
                host,
                port,
                use_ssl,
                proxy_str,
                proxy_auth_header,
                opts.verbose,
                *active_conn,
                error_out
            )) {
            return false;
        }
    } else if (opts.verbose) {
        std::cerr << "[NET] Reusing persistent connection for " << host << std::endl;
    }

    int& sock = active_conn->sock;
    SSL*& ssl = active_conn->ssl;
    auto close_active_connection = [&]() {
        close_persistent_http_connection(*active_conn);
    };

    // 7. Send Request
    std::string method = opts.method;
    std::string full_path = (!proxy_str.empty() && !use_ssl) ? url_in : path;
    
    std::string req = method + " " + full_path + " HTTP/1.1\r\n";
    req += "Host: " + host_header + "\r\n";
    req += "User-Agent: " + opts.user_agent + "\r\n";
    req += "Connection: " + std::string(allow_connection_reuse ? "keep-alive" : "close") + "\r\n";
    if (!opts.auth.empty()) req += "Authorization: Basic " + base64_encode(opts.auth) + "\r\n";
    if (!proxy_str.empty() && !use_ssl) req += proxy_auth_header;
    
    if (!opts.data.empty()) req += "Content-Length: " + std::to_string(opts.data.length()) + "\r\n";
    for (const auto& h : opts.headers) req += h + "\r\n";
    req += "\r\n";
    if (!opts.data.empty()) req += opts.data;

    if (opts.verbose) std::cerr << "[NET] Sending Request..." << std::endl;
    
    auto send_request = [&]() -> bool {
        if (use_ssl) {
            if (!ssl_write_all(ssl, req.c_str(), req.length())) {
                if (opts.verbose) ERR_print_errors_fp(stderr);
                set_error(error_out, "failed to send HTTPS request");
                return false;
            }
        } else {
            if (!write_all(sock, req.c_str(), req.length())) {
                if (opts.verbose) perror("[ERR] Write failed");
                set_error(error_out, std::string("failed to send HTTP request: ") + strerror(errno));
                return false;
            }
        }
        return true;
    };

    if (!send_request()) {
        if (reused_existing_connection) {
            close_persistent_http_connection(*active_conn);
            if (!open_http_transport_connection(
                    connect_host,
                    connect_port,
                    host,
                    port,
                    use_ssl,
                    proxy_str,
                    proxy_auth_header,
                    opts.verbose,
                    *active_conn,
                    error_out
                )) {
                return false;
            }
            if (!send_request()) {
                close_persistent_http_connection(*active_conn);
                return false;
            }
            reused_existing_connection = false;
        } else {
            close_persistent_http_connection(*active_conn);
            return false;
        }
    }

    // 8. Read Response
    std::array<char, kTransferBufferSize> buffer;
    int bytes = 0;

    long content_length = -1;
    long content_range_total = -1;
    long response_body_expected_bytes = -1;
    long total_read = 0;
    std::string header_buffer;
    std::string body_buffer;
    bool header_parsed = false;
    bool response_has_body = false;
    bool response_uses_chunked_encoding = false;
    bool server_requested_close = false;
    bool response_complete = false;
    bool response_can_reuse_connection = false;
    bool fatal_read_error = false;
    bool eof_reached = false;
    size_t chunk_bytes_remaining = 0;
    bool awaiting_chunk_size = true;
    bool parsing_chunk_trailers = false;

    auto start_time = std::chrono::steady_clock::now();
    auto last_update = start_time;
    auto last_progress = start_time;

    auto update_progress = [&](bool force) {
        if (!(opts.show_progress || opts.progress_callback) || !header_parsed) return;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count();
        if (!force && delta <= 200) return;

        double speed = 0;
        if (elapsed > 0) speed = static_cast<double>(total_read) * 1000.0 / elapsed;

        size_t progress_total = 0;
        if (content_range_total > 0) {
            progress_total = static_cast<size_t>(content_range_total);
        } else if (opts.progress_total_hint > 0) {
            progress_total = opts.progress_total_hint;
        } else if (content_length > 0) {
            progress_total = opts.progress_base_bytes + static_cast<size_t>(content_length);
        }

        size_t transferred_total = opts.progress_base_bytes + static_cast<size_t>(total_read);
        if (opts.progress_callback) {
            opts.progress_callback(transferred_total, progress_total, speed);
        }

        if (opts.show_progress) {
            int percent = 0;
            if (progress_total > 0) {
                percent = static_cast<int>((transferred_total * 100) / progress_total);
            }
            if (percent > 100) percent = 100;

            const int bar_width = 25;
            int filled = (percent * bar_width) / 100;

            std::cout << "\r[";
            for (int i = 0; i < bar_width; ++i) {
                std::cout << (i < filled ? "=" : " ");
            }
            std::cout << "] " << percent << "% (" << format_speed(speed) << ") " << std::flush;
        }

        last_update = now;
    };

    auto fail_response = [&](const std::string& message) {
        set_error(error_out, message);
        close_active_connection();
        return false;
    };
    auto current_error_or = [&](const std::string& fallback) {
        if (error_out && !error_out->empty()) return *error_out;
        return fallback;
    };

    auto flush_identity_body_buffer = [&]() -> bool {
        if (!response_has_body) {
            if (!body_buffer.empty()) {
                set_error(error_out, "unexpected response body for body-less response");
                return false;
            }
            response_complete = true;
            response_can_reuse_connection = allow_connection_reuse && !server_requested_close;
            if (opts.verbose) {
                std::cerr << "[NET] Response complete (no body)." << std::endl;
            }
            return true;
        }

        if (response_body_expected_bytes >= 0) {
            long remaining = response_body_expected_bytes - total_read;
            if (remaining < 0) {
                set_error(error_out, "received more data than declared by Content-Length");
                return false;
            }
            size_t emit_bytes = std::min(body_buffer.size(), static_cast<size_t>(remaining));
            if (emit_bytes > 0) {
                out.write(body_buffer.data(), static_cast<std::streamsize>(emit_bytes));
                total_read += static_cast<long>(emit_bytes);
                body_buffer.erase(0, emit_bytes);
            }

            if (total_read == response_body_expected_bytes) {
                if (!body_buffer.empty()) {
                    set_error(error_out, "response body exceeded declared Content-Length");
                    return false;
                }
                response_complete = true;
                response_can_reuse_connection = allow_connection_reuse && !server_requested_close;
                if (opts.verbose) {
                    std::cerr << "[NET] Response complete via Content-Length (" << total_read << " bytes)." << std::endl;
                }
            }
            return true;
        }

        if (!body_buffer.empty()) {
            out.write(body_buffer.data(), static_cast<std::streamsize>(body_buffer.size()));
            total_read += static_cast<long>(body_buffer.size());
            body_buffer.clear();
        }
        return true;
    };

    auto flush_chunked_body_buffer = [&]() -> bool {
        while (true) {
            if (parsing_chunk_trailers) {
                size_t line_end = body_buffer.find("\r\n");
                if (line_end == std::string::npos) return true;

                if (line_end == 0) {
                    body_buffer.erase(0, 2);
                    response_complete = true;
                    response_can_reuse_connection = allow_connection_reuse && !server_requested_close;
                    if (opts.verbose) {
                        std::cerr << "[NET] Response complete via chunked transfer (" << total_read << " bytes)." << std::endl;
                    }
                    return true;
                }

                body_buffer.erase(0, line_end + 2);
                continue;
            }

            if (awaiting_chunk_size) {
                size_t line_end = body_buffer.find("\r\n");
                if (line_end == std::string::npos) return true;

                std::string size_line = trim_copy(body_buffer.substr(0, line_end));
                size_t ext_pos = size_line.find(';');
                if (ext_pos != std::string::npos) {
                    size_line = trim_copy(size_line.substr(0, ext_pos));
                }

                char* end = nullptr;
                errno = 0;
                unsigned long parsed_size = std::strtoul(size_line.c_str(), &end, 16);
                if (errno != 0 || end == size_line.c_str() || (end && *end != '\0')) {
                    set_error(error_out, "invalid chunked transfer encoding");
                    return false;
                }

                chunk_bytes_remaining = static_cast<size_t>(parsed_size);
                body_buffer.erase(0, line_end + 2);
                awaiting_chunk_size = false;

                if (chunk_bytes_remaining == 0) {
                    parsing_chunk_trailers = true;
                }
            }

            if (parsing_chunk_trailers) {
                continue;
            }

            if (body_buffer.size() < chunk_bytes_remaining + 2) return true;
            if (body_buffer.compare(chunk_bytes_remaining, 2, "\r\n") != 0) {
                set_error(error_out, "malformed chunk terminator");
                return false;
            }

            if (chunk_bytes_remaining > 0) {
                out.write(body_buffer.data(), static_cast<std::streamsize>(chunk_bytes_remaining));
                total_read += static_cast<long>(chunk_bytes_remaining);
            }

            body_buffer.erase(0, chunk_bytes_remaining + 2);
            chunk_bytes_remaining = 0;
            awaiting_chunk_size = true;
        }
    };

    // Set a timeout for the socket to allow checking signals periodically
    struct timeval tv = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (!response_complete) {
        if (g_stop_sig) {
            if (opts.verbose) std::cerr << "\n[NET] Interrupted by signal." << std::endl;
            break;
        }

        if (use_ssl) {
            bytes = SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
        } else {
            bytes = read(sock, buffer.data(), buffer.size());
        }

        if (bytes <= 0) {
            if (use_ssl) {
                int ssl_err = SSL_get_error(ssl, bytes);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                if (ssl_err == SSL_ERROR_SYSCALL && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        auto now = std::chrono::steady_clock::now();
                        auto stalled_for = std::chrono::duration_cast<std::chrono::seconds>(now - last_progress).count();
                        if (stalled_for >= opts.timeout) {
                            if (opts.verbose) {
                                std::cerr << "[ERR] Download stalled for " << stalled_for << " seconds." << std::endl;
                            }
                            return fail_response(
                                "timed out after " + std::to_string(stalled_for) + " seconds without receiving data"
                            );
                        }
                        continue;
                    }
                }
                if (ssl_err == SSL_ERROR_SYSCALL && bytes == 0 && errno == 0) {
                    eof_reached = true;
                    break;
                }
                if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                    eof_reached = true;
                    break;
                }
                set_error(error_out, "TLS read failed");
                fatal_read_error = true;
                break;
            } else {
                if (bytes == 0) {
                    eof_reached = true;
                    break;
                }
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    auto now = std::chrono::steady_clock::now();
                    auto stalled_for = std::chrono::duration_cast<std::chrono::seconds>(now - last_progress).count();
                    if (stalled_for >= opts.timeout) {
                        if (opts.verbose) {
                            std::cerr << "[ERR] Download stalled for " << stalled_for << " seconds." << std::endl;
                        }
                        return fail_response(
                            "timed out after " + std::to_string(stalled_for) + " seconds without receiving data"
                        );
                    }
                    continue;
                }
                set_error(error_out, std::string("socket read failed: ") + strerror(errno));
                fatal_read_error = true;
                break;
            }
        }

        last_progress = std::chrono::steady_clock::now();

        if (!header_parsed) {
            header_buffer.append(buffer.data(), static_cast<size_t>(bytes));
            size_t header_end = header_buffer.find("\r\n\r\n");
            if (header_end == std::string::npos) continue;

            std::string headers = header_buffer.substr(0, header_end);
            std::string lower_headers = lower_copy(headers);

            int status_code = parse_http_status_code(headers);
            size_t first_line_end = headers.find("\r\n");
            std::string status_line = first_line_end == std::string::npos
                ? headers
                : headers.substr(0, first_line_end);
            bool is_redirect = status_code == 301 || status_code == 302 ||
                               status_code == 303 || status_code == 307 ||
                               status_code == 308;
            bool is_partial = status_code == 206;
            bool is_ok = status_code == 200 || status_code == 201 || is_partial;

            if (is_redirect) {
                if (!opts.follow_location) {
                    if (opts.verbose) {
                        std::cerr << "[ERR] Redirect received but redirect following is disabled: "
                                  << status_line << std::endl;
                    }
                    return fail_response("redirect received but follow_location is disabled");
                }

                std::string redirect_url = parse_header_value(headers, lower_headers, "location: ");
                if (redirect_url.empty()) {
                    if (opts.verbose) {
                        std::cerr << "[ERR] Redirect response missing Location header." << std::endl;
                    }
                    return fail_response("redirect response missing Location header");
                }
                if (redirect_url[0] == '/') {
                    redirect_url = protocol + "://" + host + redirect_url;
                }

                if (opts.verbose) std::cerr << "[NET] Following redirect to " << redirect_url << std::endl;
                close_active_connection();

                HttpOptions redirect_opts = opts;
                redirect_opts.max_redirects = opts.max_redirects - 1;
                return HttpRequestInternal(redirect_url, out, redirect_opts, error_out);
            }

            if (!is_ok) {
                if (opts.verbose) {
                    std::cerr << "[ERR] HTTP Status Error: " << status_line << std::endl;
                }
                return fail_response("HTTP status error: " + status_line);
            }

            if (opts.resume_from > 0 && !is_partial) {
                if (opts.verbose) {
                    std::cerr << "[ERR] Resume request was not honored by server: "
                              << status_line << std::endl;
                }
                return fail_response("resume request not honored");
            }

            response_has_body = opts.method != "HEAD" &&
                !((status_code >= 100 && status_code < 200) || status_code == 204 || status_code == 304);
            content_length = parse_content_length_header(headers, lower_headers);
            response_body_expected_bytes = response_has_body ? content_length : 0;
            server_requested_close = lower_copy(parse_header_value(headers, lower_headers, "connection: "))
                .find("close") != std::string::npos;
            response_uses_chunked_encoding = response_has_body &&
                lower_copy(parse_header_value(headers, lower_headers, "transfer-encoding: "))
                    .find("chunked") != std::string::npos;

            if (opts.verbose) {
                std::cerr << "[NET] Parsed response: status=" << status_code
                          << " content_length=" << content_length
                          << " chunked=" << response_uses_chunked_encoding
                          << " connection_close=" << server_requested_close
                          << " has_body=" << response_has_body
                          << std::endl;
            }

            size_t cr_pos = lower_headers.find("content-range: ");
            if (cr_pos != std::string::npos) {
                size_t val_start = cr_pos + 15;
                size_t val_end = lower_headers.find("\r\n", val_start);
                if (val_end == std::string::npos) val_end = lower_headers.size();
                std::string range_value = trim_copy(headers.substr(val_start, val_end - val_start));
                size_t slash_pos = range_value.rfind('/');
                if (slash_pos != std::string::npos) {
                    std::string total_str = trim_copy(range_value.substr(slash_pos + 1));
                    if (!total_str.empty() && total_str != "*") {
                        content_range_total = std::atol(total_str.c_str());
                    }
                }
            }

            if (opts.include_headers) {
                out.write(header_buffer.c_str(), static_cast<std::streamsize>(header_end + 4));
            }

            size_t body_offset = header_end + 4;
            if (header_buffer.length() > body_offset) {
                body_buffer.assign(header_buffer.data() + body_offset, header_buffer.length() - body_offset);
            }

            header_parsed = true;

            if (response_uses_chunked_encoding) {
                if (!flush_chunked_body_buffer()) return fail_response(current_error_or("chunked decoding failed"));
            } else {
                if (!flush_identity_body_buffer()) return fail_response(current_error_or("response body processing failed"));
            }
        } else {
            body_buffer.append(buffer.data(), static_cast<size_t>(bytes));
            if (response_uses_chunked_encoding) {
                if (!flush_chunked_body_buffer()) return fail_response(current_error_or("chunked decoding failed"));
            } else {
                if (!flush_identity_body_buffer()) return fail_response(current_error_or("response body processing failed"));
            }
        }

        update_progress(false);
    }

    if (g_stop_sig) {
        close_active_connection();
        set_error(error_out, "interrupted by signal");
        return false;
    }

    if (!header_parsed) {
        if (reused_existing_connection) {
            if (opts.verbose) {
                std::cerr << "[NET] Reused connection returned no response; retrying on a fresh socket."
                          << std::endl;
            }
            close_active_connection();
            return HttpRequestInternal(url_in, out, opts, error_out);
        }

        close_active_connection();
        if (fatal_read_error && error_out && !error_out->empty()) return false;
        set_error(error_out, "no HTTP response received");
        return false;
    }

    if (fatal_read_error) {
        close_active_connection();
        return false;
    }

    if (!response_complete) {
        if (response_uses_chunked_encoding) {
            close_active_connection();
            if (opts.verbose) {
                std::cerr << "[ERR] Incomplete chunked response." << std::endl;
            }
            set_error(error_out, "incomplete chunked response");
            return false;
        }

        if (response_body_expected_bytes >= 0) {
            close_active_connection();
            if (opts.verbose) {
                std::cerr << "[ERR] Incomplete download. Expected "
                          << response_body_expected_bytes << " bytes, got " << total_read << std::endl;
            }
            set_error(
                error_out,
                "incomplete download (" + std::to_string(total_read) + "/" +
                    std::to_string(response_body_expected_bytes) + " bytes)"
            );
            return false;
        }

        if (!eof_reached) {
            close_active_connection();
            set_error(error_out, "response terminated unexpectedly");
            return false;
        }

        if (!flush_identity_body_buffer()) {
            close_active_connection();
            return false;
        }
        response_complete = true;
        response_can_reuse_connection = false;
    }

    update_progress(true);

    if (opts.show_progress) std::cout << std::endl;

    if (!allow_connection_reuse || !response_can_reuse_connection) {
        close_active_connection();
    }

    set_error(error_out, "");
    return true;
}

// Helper to get remote file size
long GetRemoteFileSize(std::string url) {
    RemoteFileInfo info;
    if (!probe_remote_file(url, &info)) return -1;
    return info.content_length;
}

bool DownloadWorker(
    std::string url,
    std::string dest,
    long start,
    long end,
    int id,
    bool verbose,
    const std::function<void(size_t, size_t, double)>& progress_callback,
    std::string* error_out
) {
    int attempts = 0;
    const size_t range_bytes = static_cast<size_t>((end - start) + 1);
    while (attempts < 3) {
        std::ofstream out(dest, std::ios::binary | std::ios::trunc);
        if (!out) {
            set_error(error_out, "could not open range output " + dest);
            return false;
        }

        HttpOptions opts;
        opts.verbose = false; // Workers are silent
        opts.follow_location = true;
        opts.retry_count = 0;
        opts.progress_total_hint = range_bytes;
        opts.progress_callback = progress_callback;
        opts.headers.push_back("Range: bytes=" + std::to_string(start) + "-" + std::to_string(end));

        std::string last_error;
        if (HttpRequest(url, out, opts, &last_error)) return true;

        out.close();
        remove(dest.c_str());
        attempts++;
        if (attempts >= 3) {
            set_error(error_out, last_error.empty() ? "range download failed" : last_error);
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (verbose) std::cerr << "[ERR] Worker " << id << " failed after retries." << std::endl;
    return false;
}

void cleanup_download_artifacts(const std::vector<std::string>& paths) {
    for (const auto& path : paths) remove(path.c_str());
}

bool DownloadFileParallel(
    std::string url,
    const std::string& dest_path,
    long content_length,
    bool verbose,
    std::string* error_out,
    bool show_progress,
    const std::function<void(size_t, size_t, double)>& progress_callback,
    size_t* bytes_transferred_out
) {
    int num_threads = choose_parallel_thread_count(content_length);
    long part_size = content_length / num_threads;
    std::string temp_base = dest_path + ".partdownload";
    std::string temp_output = temp_base + ".merged";
    auto last_update = std::chrono::steady_clock::now();
    std::mutex progress_mutex;
    std::vector<size_t> part_progress(static_cast<size_t>(num_threads), 0);
    std::vector<double> part_speeds(static_cast<size_t>(num_threads), 0.0);
    
    if (verbose) std::cout << "Parallel Download: " << num_threads << " threads, " << (content_length/1024/1024) << " MB" << std::endl;

    std::vector<std::future<bool>> futures;
    std::vector<std::string> temp_files;
    std::vector<std::string> worker_errors(static_cast<size_t>(num_threads));

    auto emit_progress = [&](bool force) {
        auto now = std::chrono::steady_clock::now();
        if (!force && std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count() < 200) {
            return;
        }

        size_t transferred = std::accumulate(part_progress.begin(), part_progress.end(), static_cast<size_t>(0));
        double speed = std::accumulate(part_speeds.begin(), part_speeds.end(), 0.0);
        size_t total = static_cast<size_t>(std::max<long>(0, content_length));

        if (progress_callback) {
            progress_callback(transferred, total, speed);
        }

        if (show_progress) {
            int percent = 0;
            if (total > 0) {
                percent = static_cast<int>((transferred * 100) / total);
                if (percent > 100) percent = 100;
            }
            const int bar_width = 25;
            int filled = (percent * bar_width) / 100;

            std::cout << "\r[";
            for (int i = 0; i < bar_width; ++i) {
                std::cout << (i < filled ? "=" : " ");
            }
            std::cout << "] " << percent << "% (" << format_speed(speed) << ") " << std::flush;
        }

        last_update = now;
    };
    
    // Start threads
    for(int i=0; i<num_threads; i++) {
        long start = i * part_size;
        long end = (i == num_threads - 1) ? content_length - 1 : (start + part_size - 1);
        std::string temp_file = temp_base + ".part" + std::to_string(i);
        temp_files.push_back(temp_file);

        futures.push_back(std::async(
            std::launch::async,
            DownloadWorker,
            url,
            temp_file,
            start,
            end,
            i,
            verbose,
            [&, i, start, end](size_t transferred, size_t, double speed) {
                std::lock_guard<std::mutex> lock(progress_mutex);
                size_t range_bytes = static_cast<size_t>((end - start) + 1);
                part_progress[static_cast<size_t>(i)] = std::min(transferred, range_bytes);
                part_speeds[static_cast<size_t>(i)] = speed;
                emit_progress(false);
            },
            &worker_errors[static_cast<size_t>(i)]
        ));
    }
    
    // Wait for all
    bool success = true;
    for(auto& f : futures) {
        if (!f.get()) success = false;
    }
    {
        std::lock_guard<std::mutex> lock(progress_mutex);
        if (success) {
            for (size_t i = 0; i < part_progress.size(); ++i) {
                long start = static_cast<long>(i) * part_size;
                long end = (static_cast<int>(i) == num_threads - 1) ? content_length - 1 : (start + part_size - 1);
                part_progress[i] = static_cast<size_t>((end - start) + 1);
            }
        }
        emit_progress(true);
    }
    if (show_progress) std::cout << std::endl;
    
    if (success) {
        // Merge
        if (verbose) std::cout << "Merging parts..." << std::endl;
        std::ofstream final_out(temp_output, std::ios::binary | std::ios::trunc);
        if (!final_out) {
            set_error(error_out, "could not create temporary output file " + temp_output);
            success = false;
        }
        else {
            for(const auto& tf : temp_files) {
                std::ifstream part_in(tf, std::ios::binary);
                if (!part_in) {
                    set_error(error_out, "missing download part " + tf);
                    success = false;
                    break;
                }
                final_out << part_in.rdbuf();
                part_in.close();
            }
            final_out.close();
            if (success && rename(temp_output.c_str(), dest_path.c_str()) != 0) {
                set_error(error_out, std::string("failed to finalize download: ") + strerror(errno));
                success = false;
            }
        }
    }

    temp_files.push_back(temp_output);
    cleanup_download_artifacts(temp_files);
    if (success && bytes_transferred_out) {
        *bytes_transferred_out = static_cast<size_t>(content_length);
    }
    if (!success && error_out && error_out->empty()) {
        for (const auto& worker_error : worker_errors) {
            if (!worker_error.empty()) {
                set_error(error_out, worker_error);
                break;
            }
        }
        if (error_out->empty()) set_error(error_out, "parallel download failed");
    }
    return success;
}

bool DownloadFile(
    std::string url,
    const std::string& dest_path,
    bool verbose,
    std::string* error_out,
    bool show_progress,
    std::function<void(size_t, size_t, double)> progress_callback,
    size_t* bytes_transferred_out,
    long known_remote_size
) {
    set_error(error_out, "");
    if (bytes_transferred_out) *bytes_transferred_out = 0;
    std::string temp_path = dest_path + ".part";

    RemoteFileInfo remote_info;
    long size = known_remote_size > 0 ? known_remote_size : -1;
    bool have_partial = has_partial_download(temp_path);
    bool should_probe_remote = true;
    if (!have_partial &&
        known_remote_size > 0 &&
        known_remote_size <= kParallelDownloadThresholdBytes) {
        should_probe_remote = false;
    }

    bool have_remote_info = false;
    if (should_probe_remote) {
        have_remote_info = probe_remote_file(url, &remote_info);
        if (have_remote_info && remote_info.content_length > 0) {
            size = remote_info.content_length;
        }
    }

    // Use multi-part downloads only for fresh transfers when the server confirms byte ranges.
    if (!have_partial &&
        have_remote_info &&
        remote_info.content_length > kParallelDownloadThresholdBytes &&
        remote_info.accepts_ranges) {
        std::string parallel_error;
        if (DownloadFileParallel(
                url,
                dest_path,
                remote_info.content_length,
                verbose,
                &parallel_error,
                show_progress && !verbose,
                progress_callback,
                bytes_transferred_out
            )) {
            return true;
        }
        if (verbose) std::cerr << "Parallel download failed, falling back to single connection..." << std::endl;
        set_error(error_out, parallel_error);
    }

    HttpOptions opts;
    opts.verbose = verbose;
    opts.show_progress = show_progress && !verbose;
    opts.progress_callback = std::move(progress_callback);
    opts.follow_location = true;
    opts.allow_connection_reuse = true;
    opts.retry_count = 0; // Disable inner retry

    // Robust Retry Loop (Manual)
    int attempts = 0;
    int max_attempts = 5; // Increased default retries
    std::string last_error;
    
    while (attempts < max_attempts) {
        if (g_stop_sig) return false;

        if (attempts > 0) {
             if (verbose) std::cout << "Retrying download (" << attempts << "/" << max_attempts << ")..." << std::endl;
             sleep(2);
        }

        struct stat partial_stat;
        size_t resume_offset = 0;
        if (stat(temp_path.c_str(), &partial_stat) == 0 && partial_stat.st_size > 0) {
            resume_offset = static_cast<size_t>(partial_stat.st_size);
        }

        HttpOptions attempt_opts = opts;
        attempt_opts.progress_base_bytes = resume_offset;
        if (size > 0) {
            attempt_opts.progress_total_hint = static_cast<size_t>(size);
        }
        std::ios::openmode open_mode = std::ios::binary | std::ios::trunc;
        if (resume_offset > 0) {
            attempt_opts.resume_from = static_cast<long>(resume_offset);
            attempt_opts.headers.push_back("Range: bytes=" + std::to_string(resume_offset) + "-");
            open_mode = std::ios::binary | std::ios::app;
            if (progress_callback) {
                progress_callback(resume_offset, attempt_opts.progress_total_hint, 0.0);
            }
        }

        std::ofstream outfile(temp_path, open_mode);
        if (!outfile) {
            std::string message = "Could not open output file: " + temp_path;
            std::cerr << "E: " << message << std::endl;
            set_error(error_out, message);
            return false;
        }

        if (HttpRequest(url, outfile, attempt_opts, &last_error)) {
            outfile.close();
            if (rename(temp_path.c_str(), dest_path.c_str()) != 0) {
                last_error = std::string("failed to finalize download: ") + strerror(errno);
            } else {
                if (bytes_transferred_out) {
                    *bytes_transferred_out = static_cast<size_t>(std::max<long>(0, size));
                    if (*bytes_transferred_out >= resume_offset) {
                        *bytes_transferred_out -= resume_offset;
                    } else {
                        *bytes_transferred_out = 0;
                    }
                }
                set_error(error_out, "");
                return true;
            }
        } else {
            outfile.close();
            if (last_error == "resume request not honored") {
                remove(temp_path.c_str());
            }
        }

        if (attempts + 1 >= max_attempts) {
            break;
        }

        if (verbose && !last_error.empty()) {
            std::cerr << "[NET] Last failure: " << last_error << std::endl;
        }

        attempts++;
    }

    set_error(error_out, last_error);
    return false;
}
