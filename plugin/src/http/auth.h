#pragma once

#include <string>
#include "http/s_http_request.h"

enum class auth_level {
    read_only,
    standard,
    admin
};

class c_auth_manager {
public:
    c_auth_manager() = default;

    void set_token(const std::string& token) { m_required_token = token; }
    void set_enforced(bool enforced) { m_enforce_auth = enforced; }
    bool is_enabled() const { return m_enforce_auth && !m_required_token.empty(); }

    static bool constant_time_equal(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
        }
        return diff == 0;
    }

    bool is_authorized(const s_http_request& request, auth_level level) const {
        if (!m_enforce_auth || m_required_token.empty()) {
            return true;
        }

        auto it = request.headers.find("authorization");
        if (it != request.headers.end()) {
            static const std::string prefix = "Bearer ";
            const std::string& v = it->second;
            if (v.size() > prefix.size() &&
                v.compare(0, prefix.size(), prefix) == 0 &&
                constant_time_equal(v.substr(prefix.size()), m_required_token)) {
                return true;
            }
        }

        auto it2 = request.headers.find("x-auth-token");
        if (it2 != request.headers.end() && constant_time_equal(it2->second, m_required_token)) {
            return true;
        }

        return false;
    }

private:
    std::string m_required_token;
    bool m_enforce_auth = false;
};

inline c_auth_manager& get_auth_manager() {
    static c_auth_manager instance;
    return instance;
}
