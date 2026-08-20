#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_network_socket_routes(c_http_router& router) {
    // GET /api/socket/active
    router.get("/api/socket/active", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_sockets_count", 2},
            {"sockets", nlohmann::json::array({
                {{"handle", 184}, {"type", "SOCK_STREAM (TCP)"}, {"local_addr", "127.0.0.1:52134"}, {"remote_addr", "93.184.216.34:443"}, {"state", "ESTABLISHED"}},
                {{"handle", 192}, {"type", "SOCK_DGRAM (UDP)"}, {"local_addr", "0.0.0.0:53211"}, {"remote_addr", "8.8.8.8:53"}, {"state", "CONNECTED"}}
            })}
        });
    });

    // GET /api/socket/buffers
    router.get("/api/socket/buffers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"captured_buffers_count", 1},
            {"buffers", nlohmann::json::array({
                {{"socket", 184}, {"direction", "SEND"}, {"size", 84}, {"preview_ascii", "GET /api/v1/update HTTP/1.1\\r\\nHost: example.com\\r\\n"}}
            })}
        });
    });

    // GET /api/socket/history
    router.get("/api/socket/history", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"connection_history_count", 3}
        });
    });

    // GET /api/socket/dns_queries
    router.get("/api/socket/dns_queries", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dns_queries", nlohmann::json::array({
                {{"domain", "api.update-service.org"}, {"resolved_ip", "93.184.216.34"}}
            })}
        });
    });
}

} // namespace handlers
