#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <iostream>
#include <vector>

struct HttpOptions {
    bool verbose = false;
    bool show_progress = false;
    bool include_headers = false;
    bool head_only = false;
    bool follow_location = false;
    bool insecure = true;
    int max_redirects = 5;
    int timeout = 30;
    int retry_count = 3;      // Number of retries on failure
    int retry_delay = 2;      // Seconds to wait between retries
    std::string proxy;
    std::string method = "GET";
    std::string user_agent = "GeminiOS/1.0";
    std::string auth;
    std::string data;
    std::vector<std::string> headers;
};

// Generic HTTP Request
bool HttpRequest(const std::string& url, std::ostream& out, const HttpOptions& opts);

// Configure Network Interface (eth0)
void ConfigureNetwork();

// Resolve Hostname to IP
std::string ResolveDNS(const std::string& host);

// Downloads a file from an HTTPS URL to a local path
bool DownloadFile(std::string url, const std::string& dest_path, bool verbose = false);

#endif // NETWORK_H
