#pragma once

#include <string>
#include <mutex>
#include <chrono>
#include <fstream>
#include "http/s_http_request.h"

class c_audit_logger {
public:
    c_audit_logger() = default;
    ~c_audit_logger() = default;

    c_audit_logger(const c_audit_logger&) = delete;
    c_audit_logger& operator=(const c_audit_logger&) = delete;
    c_audit_logger(c_audit_logger&&) = delete;
    c_audit_logger& operator=(c_audit_logger&&) = delete;

    void log_request(const s_http_request& request, int status_code, const std::string& client_ip);
    void log_auth_failure(const std::string& client_ip, const std::string& path);
    void cleanup();
    nlohmann::json get_recent(int limit = 100);
    nlohmann::json get_stats();
    void clear();

private:
    mutable std::mutex m_mutex;
    std::chrono::steady_clock::time_point m_last_cleanup = std::chrono::steady_clock::now();
    static constexpr const char* LOG_FILE = "mcp_audit.log";
};

inline c_audit_logger& get_audit_logger() {
    static c_audit_logger instance;
    return instance;
}

inline void c_audit_logger::log_request(const s_http_request& request, int status_code, const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream log(LOG_FILE, std::ios::app);
    if (!log.is_open()) return;

    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::system_clock::to_time_t(now);
    char buf[64];
    ctime_s(buf, sizeof(buf), &ts);
    buf[strcspn(buf, "\n")] = '\0';

    log << buf << " | " << request.method << " " << request.path
        << " | IP=" << client_ip << " | Status=" << status_code << "\n";
}

inline void c_audit_logger::log_auth_failure(const std::string& client_ip, const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream log(LOG_FILE, std::ios::app);
    if (!log.is_open()) return;

    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::system_clock::to_time_t(now);
    char buf[64];
    ctime_s(buf, sizeof(buf), &ts);
    buf[strcspn(buf, "\n")] = '\0';

    log << buf << " | AUTH FAIL | IP=" << client_ip << " | Path=" << path << "\n";
}

inline void c_audit_logger::cleanup() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_last_cleanup = std::chrono::steady_clock::now();
}

inline nlohmann::json c_audit_logger::get_recent(int limit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto entries = nlohmann::json::array();
    std::ifstream file(LOG_FILE);
    if (!file.is_open()) return entries;

    std::string line;
    std::vector<std::string> lines;
    while (std::getline(file, line)) {
        if (!line.empty()) lines.push_back(line);
    }

    int start = static_cast<int>(lines.size()) > limit ? static_cast<int>(lines.size()) - limit : 0;
    for (size_t i = start; i < lines.size(); ++i) {
        entries.push_back(lines[i]);
    }
    return entries;
}

inline nlohmann::json c_audit_logger::get_stats() {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t line_count = 0;
    std::ifstream file(LOG_FILE);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) ++line_count;
        }
    }
    return {
        {"total_entries", line_count},
        {"log_file", LOG_FILE}
    };
}

inline void c_audit_logger::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream file(LOG_FILE, std::ios::trunc);
}
