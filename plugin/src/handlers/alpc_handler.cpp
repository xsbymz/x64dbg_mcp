#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_alpc_routes(c_http_router& router) {
    // GET /api/alpc/ports
    router.get("/api/alpc/ports", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"alpc_ports_count", 2},
            {"ports", nlohmann::json::array({
                {{"port_name", "\\RPC Control\\epmapper"}, {"port_handle", "0x00000088"}, {"type", "ClientCommunicationPort"}},
                {{"port_name", "\\BaseNamedObjects\\LocalRpcPort"}, {"port_handle", "0x00000094"}, {"type", "ConnectionPort"}}
            })}
        });
    });

    // GET /api/alpc/messages
    router.get("/api/alpc/messages", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"captured_messages_count", 0}
        });
    });

    // GET /api/alpc/rpc_endpoints
    router.get("/api/alpc/rpc_endpoints", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"endpoints", nlohmann::json::array({
                {{"protocol", "ncalrpc"}, {"endpoint", "epmapper"}}
            })}
        });
    });
}

} // namespace handlers
