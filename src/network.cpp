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
};

std::mutex g_remote_file_info_mutex;
std::unordered_map<std::string, RemoteFileInfo> g_remote_file_info_cache;

long parse_content_length_header(const std::string& headers, const std::string& lower_headers) {
    size_t pos = lower_headers.find("content-length: ");
    if (pos == std::string::npos) return -1;

    size_t end = lower_headers.find("\r\n", pos);
    if (end == std::string::npos) return -1;
    return std::atol(headers.substr(pos + 16, end - (pos + 16)).c_str());
}

bool parse_accept_ranges_header(const std::string& lower_headers) {
    size_t pos = lower_headers.find("accept-ranges: ");
    if (pos == std::string::npos) return false;

    size_t end = lower_headers.find("\r\n", pos);
    if (end == std::string::npos) return false;
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
    opts.verbose = false;

    std::stringstream ss;
    if (!HttpRequest(url, ss, opts)) return false;

    std::string response = ss.str();
    std::string lower_response = response;
    std::transform(lower_response.begin(), lower_response.end(), lower_response.begin(), ::tolower);

    RemoteFileInfo parsed;
    parsed.content_length = parse_content_length_header(response, lower_response);
    parsed.accepts_ranges = parse_accept_ranges_header(lower_response);

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
    std::string host;
    std::string path;

    size_t slash_pos = url_part.find('/');
    if (slash_pos != std::string::npos) {
        host = url_part.substr(0, slash_pos);
        path = url_part.substr(slash_pos);
    } else {
        host = url_part;
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

    // Resolve
    std::string ip = ResolveDNS(connect_host);
    if (ip.empty()) {
        if (opts.verbose) std::cerr << "[ERR] Could not resolve: " << connect_host << std::endl;
        set_error(error_out, "could not resolve " + connect_host);
        return false;
    }
    if (opts.verbose) std::cerr << "[NET] Connecting to IP: " << ip << std::endl;

    if (g_stop_sig) return false;

    // 5. Socket Connection
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        if (opts.verbose) perror("[ERR] Socket creation failed");
        set_error(error_out, std::string("socket creation failed: ") + strerror(errno));
        return false;
    }
    configure_transfer_socket(sock);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(connect_port);
    inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        if (opts.verbose) perror("[ERR] Connection failed");
        set_error(error_out, std::string("connection failed: ") + strerror(errno));
        close(sock);
        return false;
    }

    // 6. SSL Setup
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;

    if (!proxy_str.empty() && use_ssl) {
        std::string connect_req = "CONNECT " + host + ":" + std::to_string(port) + " HTTP/1.1\r\n";
        connect_req += "Host: " + host + ":" + std::to_string(port) + "\r\n";
        connect_req += proxy_auth_header;
        connect_req += "\r\n";
        
        if (opts.verbose) std::cerr << "[NET] Sending Proxy CONNECT..." << std::endl;
        if (!write_all(sock, connect_req.c_str(), connect_req.length())) {
            set_error(error_out, std::string("failed to send proxy CONNECT request: ") + strerror(errno));
            close(sock);
            return false;
        }
        
        char tmp[1024];
        int len = read(sock, tmp, sizeof(tmp)-1);
        if (len > 0) {
            tmp[len] = 0;
            if (std::string(tmp).find("200") == std::string::npos) {
                if (opts.verbose) std::cerr << "[ERR] Proxy CONNECT failed: " << tmp << std::endl;
                set_error(error_out, "proxy CONNECT failed");
                close(sock); return false;
            }
        }
    }

    if (use_ssl) {
        SSL_library_init();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            if (opts.verbose) std::cerr << "[ERR] SSL Context failed" << std::endl;
            set_error(error_out, "failed to initialize SSL context");
            close(sock); return false;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY | SSL_MODE_RELEASE_BUFFERS);

        ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, host.c_str());
        SSL_set_fd(ssl, sock);

        if (SSL_connect(ssl) <= 0) {
            if (opts.verbose) ERR_print_errors_fp(stderr);
            set_error(error_out, "TLS handshake failed");
            SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
            return false;
        }
    }

    // 7. Send Request
    std::string method = opts.method;
    std::string full_path = (!proxy_str.empty() && !use_ssl) ? url_in : path;
    
    std::string req = method + " " + full_path + " HTTP/1.1\r\n";
    req += "Host: " + host + "\r\n";
    req += "User-Agent: " + opts.user_agent + "\r\n";
    req += "Connection: close\r\n";
    if (!opts.auth.empty()) req += "Authorization: Basic " + base64_encode(opts.auth) + "\r\n";
    if (!proxy_str.empty() && !use_ssl) req += proxy_auth_header;
    
    if (!opts.data.empty()) req += "Content-Length: " + std::to_string(opts.data.length()) + "\r\n";
    for (const auto& h : opts.headers) req += h + "\r\n";
    req += "\r\n";
    if (!opts.data.empty()) req += opts.data;

    if (opts.verbose) std::cerr << "[NET] Sending Request..." << std::endl;
    
    if (use_ssl) {
        if (!ssl_write_all(ssl, req.c_str(), req.length())) {
            if (opts.verbose) ERR_print_errors_fp(stderr);
            set_error(error_out, "failed to send HTTPS request");
            SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
            return false;
        }
    } else {
        if (!write_all(sock, req.c_str(), req.length())) {
            if (opts.verbose) perror("[ERR] Write failed");
            set_error(error_out, std::string("failed to send HTTP request: ") + strerror(errno));
            close(sock); return false;
        }
    }

    // 8. Read Response
    std::array<char, kTransferBufferSize> buffer;
    int bytes;
    
    long content_length = -1;
    long content_range_total = -1;
    long total_read = 0;
    std::string header_buffer;
    bool header_parsed = false;
    
    auto start_time = std::chrono::steady_clock::now();
    auto last_update = start_time;
    auto last_progress = start_time;
    
    // Set a timeout for the socket to allow checking signals periodically
    struct timeval tv = {1, 0}; // 1 second timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (true) {
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
                // Check if it's a real error or just clean close
                if (ssl_err == SSL_ERROR_SYSCALL && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                     if (errno == EINTR) continue; // Signal handled, loop will check g_stop_sig
                     if (errno == EAGAIN || errno == EWOULDBLOCK) {
                         auto now = std::chrono::steady_clock::now();
                         auto stalled_for = std::chrono::duration_cast<std::chrono::seconds>(now - last_progress).count();
                         if (stalled_for >= opts.timeout) {
                             if (opts.verbose) std::cerr << "[ERR] Download stalled for " << stalled_for << " seconds." << std::endl;
                             set_error(error_out, "timed out after " + std::to_string(stalled_for) + " seconds without receiving data");
                             if (use_ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
                             close(sock);
                             return false;
                         }
                         continue; // Timeout, check g_stop_sig
                     }
                }
                if (ssl_err != SSL_ERROR_ZERO_RETURN) {
                    set_error(error_out, "TLS read failed");
                }
                break; // Real error or close
            } else {
                if (bytes < 0) {
                     if (errno == EINTR) continue;
                     if (errno == EAGAIN || errno == EWOULDBLOCK) {
                         auto now = std::chrono::steady_clock::now();
                         auto stalled_for = std::chrono::duration_cast<std::chrono::seconds>(now - last_progress).count();
                         if (stalled_for >= opts.timeout) {
                             if (opts.verbose) std::cerr << "[ERR] Download stalled for " << stalled_for << " seconds." << std::endl;
                             set_error(error_out, "timed out after " + std::to_string(stalled_for) + " seconds without receiving data");
                             close(sock);
                             return false;
                         }
                         continue;
                     }
                     set_error(error_out, std::string("socket read failed: ") + strerror(errno));
                }
                break; // EOF or Error
            }
        }

        last_progress = std::chrono::steady_clock::now();

        if (!header_parsed && !opts.include_headers) {
             header_buffer.append(buffer.data(), bytes);
             size_t header_end = header_buffer.find("\r\n\r\n");
             if (header_end != std::string::npos) {
                 std::string headers = header_buffer.substr(0, header_end);
                 std::string lower_headers = headers;
                 std::transform(lower_headers.begin(), lower_headers.end(), lower_headers.begin(), ::tolower);

                 // Check HTTP Status
                 size_t first_line_end = headers.find("\r\n");
                 if (first_line_end != std::string::npos) {
                     std::string status_line = headers.substr(0, first_line_end);
                     bool is_redirect = status_line.find(" 302 ") != std::string::npos ||
                                        status_line.find(" 301 ") != std::string::npos;
                     bool is_partial = status_line.find(" 206 ") != std::string::npos;
                     bool is_ok = status_line.find(" 200 ") != std::string::npos ||
                                  status_line.find(" 201 ") != std::string::npos ||
                                  is_partial;
                     if (is_redirect) {
                         if (!opts.follow_location) {
                             if (opts.verbose) std::cerr << "[ERR] Redirect received but redirect following is disabled: " << status_line << std::endl;
                             set_error(error_out, "redirect received but follow_location is disabled");
                             if (use_ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
                             close(sock);
                             return false;
                         }

                         size_t loc_pos = lower_headers.find("location: ");
                         if (loc_pos == std::string::npos) {
                             if (opts.verbose) std::cerr << "[ERR] Redirect response missing Location header." << std::endl;
                             set_error(error_out, "redirect response missing Location header");
                             if (use_ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
                             close(sock);
                             return false;
                         }

                         size_t loc_start = loc_pos + 10;
                         size_t loc_end = lower_headers.find("\r\n", loc_start);
                         std::string redirect_url = trim_copy(headers.substr(loc_start, loc_end - loc_start));
                         if (!redirect_url.empty() && redirect_url[0] == '/') {
                             redirect_url = protocol + "://" + host + redirect_url;
                         }

                         if (opts.verbose) std::cerr << "[NET] Following redirect to " << redirect_url << std::endl;
                         if (use_ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
                         close(sock);

                         HttpOptions redirect_opts = opts;
                         redirect_opts.max_redirects = opts.max_redirects - 1;
                         return HttpRequestInternal(redirect_url, out, redirect_opts, error_out);
                     }

                     if (!is_ok) {
                         if (opts.verbose) std::cerr << "[ERR] HTTP Status Error: " << status_line << std::endl;
                         set_error(error_out, "HTTP status error: " + status_line);
                         if (use_ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
                         close(sock);
                         return false; 
                     }

                     if (opts.resume_from > 0 && !is_partial) {
                         if (opts.verbose) {
                             std::cerr << "[ERR] Resume request was not honored by server: "
                                       << status_line << std::endl;
                         }
                         set_error(error_out, "resume request not honored");
                         if (use_ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
                         close(sock);
                         return false;
                     }
                 }
                 
                 // Look for Content-Length
                 size_t cl_pos = lower_headers.find("content-length: ");
                 if (cl_pos != std::string::npos) {
                     size_t val_start = cl_pos + 16;
                     size_t val_end = lower_headers.find("\r\n", val_start);
                     if (val_end != std::string::npos) {
                         content_length = std::atol(headers.substr(val_start, val_end - val_start).c_str());
                     }
                 }

                 size_t cr_pos = lower_headers.find("content-range: ");
                 if (cr_pos != std::string::npos) {
                     size_t val_start = cr_pos + 15;
                     size_t val_end = lower_headers.find("\r\n", val_start);
                     if (val_end != std::string::npos) {
                         std::string range_value = trim_copy(headers.substr(val_start, val_end - val_start));
                         size_t slash_pos = range_value.rfind('/');
                         if (slash_pos != std::string::npos) {
                             std::string total_str = trim_copy(range_value.substr(slash_pos + 1));
                             if (!total_str.empty() && total_str != "*") {
                                 content_range_total = std::atol(total_str.c_str());
                             }
                         }
                     }
                 }
                 
                 out.write(header_buffer.c_str() + header_end + 4, header_buffer.length() - (header_end + 4));
                 total_read += (header_buffer.length() - (header_end + 4));
                 header_parsed = true;
             }
        } else {
             out.write(buffer.data(), bytes);
             total_read += bytes;
        }
        
        if ((opts.show_progress || opts.progress_callback) && header_parsed) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
            auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count();

            if (delta > 200 || bytes <= 0) { // Update every 200ms
                 double speed = 0;
                 if (elapsed > 0) speed = (double)total_read * 1000.0 / elapsed;
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
                     if (progress_total > 0) percent = (int)((transferred_total * 100) / progress_total);
                     if (percent > 100) percent = 100;

                     // Bar: [===              ]
                     int bar_width = 25;
                     int filled = (percent * bar_width) / 100;

                     std::cout << "\r[";
                     for(int i=0; i<bar_width; i++) {
                         if (i < filled) std::cout << "=";
                         else std::cout << " ";
                     }
                     std::cout << "] " << percent << "% (" << format_speed(speed) << ") " << std::flush;
                 }

                 last_update = now;
            }
        }
    }
    
    // Check if we were interrupted
    if (g_stop_sig) {
         set_error(error_out, "interrupted by signal");
         if (use_ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
         close(sock);
         return false;
    }

    // Force final progress update to 100% if valid download
    if ((opts.show_progress || opts.progress_callback) && header_parsed && content_length > 0 && total_read >= content_length) {
         auto now = std::chrono::steady_clock::now();
         auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
         double speed = 0;
         if (elapsed > 0) speed = (double)total_read * 1000.0 / elapsed;
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
             int percent = 100;
             int bar_width = 25;

             std::cout << "\r[";
             for(int i=0; i<bar_width; i++) std::cout << "=";
             std::cout << "] " << percent << "% (" << format_speed(speed) << ") " << std::flush;
         }
    }

    if (opts.show_progress) std::cout << std::endl;

    if (use_ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    close(sock);
    if (content_length > 0 && total_read != content_length && opts.method != "HEAD") {
        if (opts.verbose) std::cerr << "[ERR] Incomplete download. Expected " << content_length << " bytes, got " << total_read << std::endl;
        set_error(error_out, "incomplete download (" + std::to_string(total_read) + "/" + std::to_string(content_length) + " bytes)");
        return false;
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
    size_t* bytes_transferred_out
) {
    set_error(error_out, "");
    if (bytes_transferred_out) *bytes_transferred_out = 0;
    std::string temp_path = dest_path + ".part";

    RemoteFileInfo remote_info;
    long size = -1;
    bool have_remote_info = probe_remote_file(url, &remote_info);
    if (have_remote_info) size = remote_info.content_length;

    // Use multi-part downloads only for fresh transfers when the server confirms byte ranges.
    if (!has_partial_download(temp_path) &&
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
