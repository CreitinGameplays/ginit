#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <functional>
#include <iostream>
#include <vector>

struct HttpOptions {
    bool verbose = false;
    bool show_progress = false;
    bool include_headers = false;
    bool head_only = false;
    bool follow_location = false;
    bool allow_connection_reuse = false;
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
    std::function<void(size_t, size_t, double)> progress_callback;
    size_t progress_base_bytes = 0;
    size_t progress_total_hint = 0;
    long resume_from = 0;
};

// Generic HTTP Request
bool HttpRequest(const std::string& url, std::ostream& out, const HttpOptions& opts, std::string* error_out = nullptr);

// Configure Network Interface (eth0)
int ConfigureNetwork();

// Resolve Hostname to IP
std::string ResolveDNS(const std::string& host);

// Query the remote object size using an HTTP HEAD request.
long GetRemoteFileSize(std::string url);

// Downloads a file from an HTTPS URL to a local path.
// `verbose` enables low-level network logging.
// `show_progress` controls the built-in per-file progress bar.
bool DownloadFile(
    std::string url,
    const std::string& dest_path,
    bool verbose = false,
    std::string* error_out = nullptr,
    bool show_progress = true,
    std::function<void(size_t, size_t, double)> progress_callback = nullptr,
    size_t* bytes_transferred_out = nullptr,
    long known_remote_size = -1
);

#endif // NETWORK_H
