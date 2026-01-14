#include "network.h"
#include "signals.h"
#include "debug.h"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
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

// QEMU Default Network Settings
#define MY_IP "10.0.2.15"
#define GATEWAY "10.0.2.2"
#define NETMASK "255.255.255.0"
#define DNS_SERVER "10.0.2.3" // QEMU User Network DNS

void ConfigureNetwork() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

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
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);

    // 1. Set IP Address
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, MY_IP, &addr->sin_addr);
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        perror("[NET] Failed to set IP");
        close(sock); return;
    }

    // 2. Bring Interface UP
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("[NET] Failed to get flags");
        close(sock); return;
    }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("[NET] Failed to bring up eth0");
        close(sock); return;
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
    route.rt_dev = (char*)"eth0"; // Explicitly bind to eth0

    if (ioctl(sock, SIOCADDRT, &route) < 0) {
        if (errno != EEXIST) LOG_DEBUG("Failed to set gateway: " << strerror(errno));
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

bool HttpRequestInternal(const std::string& url_in, std::ostream& out, const HttpOptions& opts);

bool HttpRequest(const std::string& url, std::ostream& out, const HttpOptions& opts) {
    int attempts = 0;
    int max_attempts = opts.retry_count + 1;
    
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
        
        if (HttpRequestInternal(url, out, opts)) {
            return true;
        }
        
        attempts++;
        if (g_stop_sig) return false;
    }
    
    return false;
}

bool HttpRequestInternal(const std::string& url_in, std::ostream& out, const HttpOptions& opts) {
    if (opts.max_redirects < 0) {
        if (opts.verbose) std::cerr << "[NET] Max redirects reached" << std::endl;
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
        return false;
    }
    if (opts.verbose) std::cerr << "[NET] Connecting to IP: " << ip << std::endl;

    if (g_stop_sig) return false;

    // 5. Socket Connection
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        if (opts.verbose) perror("[ERR] Socket creation failed");
        return false;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(connect_port);
    inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        if (opts.verbose) perror("[ERR] Connection failed");
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
        write(sock, connect_req.c_str(), connect_req.length());
        
        char tmp[1024];
        int len = read(sock, tmp, sizeof(tmp)-1);
        if (len > 0) {
            tmp[len] = 0;
            if (std::string(tmp).find("200") == std::string::npos) {
                if (opts.verbose) std::cerr << "[ERR] Proxy CONNECT failed: " << tmp << std::endl;
                close(sock); return false;
            }
        }
    }

    if (use_ssl) {
        SSL_library_init();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            if (opts.verbose) std::cerr << "[ERR] SSL Context failed" << std::endl;
            close(sock); return false;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

        ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, host.c_str());
        SSL_set_fd(ssl, sock);

        if (SSL_connect(ssl) <= 0) {
            if (opts.verbose) ERR_print_errors_fp(stderr);
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
        if (SSL_write(ssl, req.c_str(), req.length()) <= 0) {
            if (opts.verbose) ERR_print_errors_fp(stderr);
            SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
            return false;
        }
    } else {
        if (write(sock, req.c_str(), req.length()) < 0) {
            if (opts.verbose) perror("[ERR] Write failed");
            close(sock); return false;
        }
    }

    // 8. Read Response
    char buffer[4096];
    int bytes;
    
    long content_length = -1;
    long total_read = 0;
    std::string header_buffer;
    bool header_parsed = false;
    
    auto start_time = std::chrono::steady_clock::now();
    auto last_update = start_time;
    
    // Set a timeout for the socket to allow checking signals periodically
    struct timeval tv = {1, 0}; // 1 second timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (true) {
        if (g_stop_sig) {
            if (opts.verbose) std::cerr << "\n[NET] Interrupted by signal." << std::endl;
            break;
        }

        if (use_ssl) {
            bytes = SSL_read(ssl, buffer, sizeof(buffer));
        } else {
            bytes = read(sock, buffer, sizeof(buffer));
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
                     if (errno == EAGAIN || errno == EWOULDBLOCK) continue; // Timeout, check g_stop_sig
                }
                break; // Real error or close
            } else {
                if (bytes < 0) {
                     if (errno == EINTR) continue;
                     if (errno == EAGAIN || errno == EWOULDBLOCK) continue; 
                }
                break; // EOF or Error
            }
        }

        if (!header_parsed && !opts.include_headers) {
             header_buffer.append(buffer, bytes);
             size_t header_end = header_buffer.find("\r\n\r\n");
             if (header_end != std::string::npos) {
                 std::string headers = header_buffer.substr(0, header_end);

                 // Check HTTP Status
                 size_t first_line_end = headers.find("\r\n");
                 if (first_line_end != std::string::npos) {
                     std::string status_line = headers.substr(0, first_line_end);
                     if (status_line.find(" 200 ") == std::string::npos && 
                         status_line.find(" 201 ") == std::string::npos && 
                         status_line.find(" 206 ") == std::string::npos &&
                         status_line.find(" 302 ") == std::string::npos &&
                         status_line.find(" 301 ") == std::string::npos) {
                         if (opts.verbose) std::cerr << "[ERR] HTTP Status Error: " << status_line << std::endl;
                         if (use_ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
                         close(sock);
                         return false; 
                     }
                 }
                 
                 // Look for Content-Length
                 std::string lower_headers = headers;
                 std::transform(lower_headers.begin(), lower_headers.end(), lower_headers.begin(), ::tolower);
                 
                 size_t cl_pos = lower_headers.find("content-length: ");
                 if (cl_pos != std::string::npos) {
                     size_t val_start = cl_pos + 16;
                     size_t val_end = lower_headers.find("\r\n", val_start);
                     if (val_end != std::string::npos) {
                         content_length = std::atol(headers.substr(val_start, val_end - val_start).c_str());
                     }
                 }
                 
                 out.write(header_buffer.c_str() + header_end + 4, header_buffer.length() - (header_end + 4));
                 total_read += (header_buffer.length() - (header_end + 4));
                 header_parsed = true;
             }
        } else {
             out.write(buffer, bytes);
             total_read += bytes;
        }
        
        if (opts.show_progress && header_parsed) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
            auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count();

            if (delta > 200 || bytes <= 0) { // Update every 200ms
                 double speed = 0;
                 if (elapsed > 0) speed = (double)total_read * 1000.0 / elapsed;
                 
                 int percent = 0;
                 if (content_length > 0) percent = (int)((total_read * 100) / content_length);
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
                 last_update = now;
            }
        }
    }
    
    // Check if we were interrupted
    if (g_stop_sig) {
         if (use_ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
         close(sock);
         return false;
    }

    // Force final progress update to 100% if valid download
    if (opts.show_progress && header_parsed && content_length > 0 && total_read >= content_length) {
         auto now = std::chrono::steady_clock::now();
         auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
         double speed = 0;
         if (elapsed > 0) speed = (double)total_read * 1000.0 / elapsed;
         
         int percent = 100;
         int bar_width = 25;
         
         std::cout << "\r[";
         for(int i=0; i<bar_width; i++) std::cout << "=";
         std::cout << "] " << percent << "% (" << format_speed(speed) << ") " << std::flush;
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
        return false;
    }
    return true;
}

// Helper to get remote file size
long GetRemoteFileSize(std::string url) {
    HttpOptions opts;
    opts.method = "HEAD";
    opts.include_headers = true; 
    opts.verbose = false;
    
    std::stringstream ss;
    if (!HttpRequest(url, ss, opts)) return -1;
    
    std::string response = ss.str();
    
    // Parse Content-Length
    std::string lower_resp = response;
    std::transform(lower_resp.begin(), lower_resp.end(), lower_resp.begin(), ::tolower);
    size_t pos = lower_resp.find("content-length: ");
    if (pos != std::string::npos) {
        size_t end = lower_resp.find("\r\n", pos);
        if (end != std::string::npos) {
            std::string val = response.substr(pos + 16, end - (pos + 16));
            return std::atol(val.c_str());
        }
    }
    return -1;
}

bool DownloadWorker(std::string url, std::string dest, long start, long end, int id, bool verbose) {
    int attempts = 0;
    while(attempts < 3) {
        std::ofstream out(dest, std::ios::binary);
        if (!out) return false;
        
        HttpOptions opts;
        opts.verbose = false; // Workers are silent
        opts.headers.push_back("Range: bytes=" + std::to_string(start) + "-" + std::to_string(end));
        
        if (HttpRequest(url, out, opts)) return true;
        
        attempts++;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (verbose) std::cerr << "[ERR] Worker " << id << " failed after retries." << std::endl;
    return false;
}

bool DownloadFileParallel(std::string url, const std::string& dest_path, long content_length, bool verbose) {
    int num_threads = 4;
    long part_size = content_length / num_threads;
    
    if (verbose) std::cout << "Parallel Download: " << num_threads << " threads, " << (content_length/1024/1024) << " MB" << std::endl;

    std::vector<std::future<bool>> futures;
    std::vector<std::string> temp_files;
    
    // Start threads
    for(int i=0; i<num_threads; i++) {
        long start = i * part_size;
        long end = (i == num_threads - 1) ? content_length - 1 : (start + part_size - 1);
        std::string temp_file = dest_path + ".part" + std::to_string(i);
        temp_files.push_back(temp_file);
        
        futures.push_back(std::async(std::launch::async, DownloadWorker, url, temp_file, start, end, i, verbose));
    }
    
    // Wait for all
    bool success = true;
    for(auto& f : futures) {
        if (!f.get()) success = false;
    }
    
    if (success) {
        // Merge
        if (verbose) std::cout << "Merging parts..." << std::endl;
        std::ofstream final_out(dest_path, std::ios::binary);
        if (!final_out) success = false;
        else {
            for(const auto& tf : temp_files) {
                std::ifstream part_in(tf, std::ios::binary);
                final_out << part_in.rdbuf();
                part_in.close();
                remove(tf.c_str());
            }
        }
    } else {
        // Cleanup
        for(const auto& tf : temp_files) remove(tf.c_str());
    }
    
    return success;
}

bool DownloadFile(std::string url, const std::string& dest_path, bool verbose) {
    // Check if parallel download is suitable
    long size = GetRemoteFileSize(url);
    if (size > 5 * 1024 * 1024) { // > 5 MB use parallel
        if (DownloadFileParallel(url, dest_path, size, verbose)) return true;
        if (verbose) std::cerr << "Parallel download failed, falling back to single connection..." << std::endl;
    }

    HttpOptions opts;
    opts.verbose = verbose;
    opts.show_progress = !verbose; 
    opts.follow_location = true;
    opts.retry_count = 0; // Disable inner retry

    // Robust Retry Loop (Manual)
    int attempts = 0;
    int max_attempts = 5; // Increased default retries
    
    while (attempts < max_attempts) {
        if (g_stop_sig) return false;

        if (attempts > 0) {
             if (verbose) std::cout << "Retrying download (" << attempts << "/" << max_attempts << ")..." << std::endl;
             sleep(2);
        }

        // Always truncate/reset file on each attempt
        std::ofstream outfile(dest_path, std::ios::binary);
        if (!outfile) {
            std::cerr << "E: Could not open output file: " << dest_path << std::endl;
            return false;
        }

        if (HttpRequest(url, outfile, opts)) {
            return true;
        }
        
        outfile.close(); // Flush and close
        attempts++;
    }
    
    return false;
}
