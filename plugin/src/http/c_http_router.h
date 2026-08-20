#pragma once

#include <string>
#include <unordered_map>
#include <functional>

#include "http/s_http_request.h"
#include "http/s_http_response.h"

// Route handler function signature
using route_handler_t = std::function<s_http_response(const s_http_request&)>;

class c_http_router {
public:
    // Register a route
    void add_route(const std::string& method, const std::string& path, route_handler_t handler);

    // Convenience helpers
    void get(const std::string& path, route_handler_t handler);
    void post(const std::string& path, route_handler_t handler);

    // Dispatch a request to the appropriate handler (O(1) lookup)
    [[nodiscard]] s_http_response dispatch(const s_http_request& request) const;

    // Get total registered route count
    [[nodiscard]] size_t route_count() const noexcept { return m_routes.size(); }

private:
    // Key format: "METHOD /path" e.g. "GET /api/debug/state"
    std::unordered_map<std::string, route_handler_t> m_routes;
};
