#pragma once

#include <string>
#include <unordered_map>
#include <deque>
#include <mutex>
#include <chrono>
#include <nlohmann/json.hpp>

class c_rate_limiter {
public:
    c_rate_limiter() = default;

    bool allow_connection(const std::string& client_ip);
    void record_connection(const std::string& client_ip);
    nlohmann::json get_stats();

private:
    static constexpr int WINDOW_SECONDS = 60;
    static constexpr int MAX_CONNECTIONS_PER_IP = 30;

    struct s_entry {
        std::deque<std::chrono::steady_clock::time_point> timestamps;
    };

    std::mutex m_mutex;
    std::unordered_map<std::string, s_entry> m_entries;

    void cleanup_expired(s_entry& entry);
};

inline c_rate_limiter& get_rate_limiter() {
    static c_rate_limiter instance;
    return instance;
}

inline nlohmann::json c_rate_limiter::get_stats() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return {
        {"concurrent_connections", static_cast<int>(m_entries.size())},
        {"window_seconds", WINDOW_SECONDS},
        {"max_connections_per_ip", MAX_CONNECTIONS_PER_IP}
    };
}

inline bool c_rate_limiter::allow_connection(const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_entries.find(client_ip);
    if (it == m_entries.end()) {
        return true;
    }
    cleanup_expired(it->second);
    return it->second.timestamps.size() < MAX_CONNECTIONS_PER_IP;
}

inline void c_rate_limiter::record_connection(const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& entry = m_entries[client_ip];
    entry.timestamps.push_back(std::chrono::steady_clock::now());
    cleanup_expired(entry);
}

inline void c_rate_limiter::cleanup_expired(s_entry& entry) {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(WINDOW_SECONDS);
    while (!entry.timestamps.empty() && entry.timestamps.front() < cutoff) {
        entry.timestamps.pop_front();
    }
}
