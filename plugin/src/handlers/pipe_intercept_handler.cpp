#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pipe_intercept_routes(c_http_router& router) {
    // GET /api/pipe_intercept/list
    router.get("/api/pipe_intercept/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"intercepted_pipes_count", 1},
            {"pipes", nlohmann::json::array({
                {{"pipe_name", "\\\\.\\pipe\\AgentIpcChannel"}, {"handles_count", 2}, {"total_bytes_transferred", 2048}}
            })}
        });
    });

    // POST /api/pipe_intercept/stream
    router.post("/api/pipe_intercept/stream", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string pname = body.value("pipe_name", "\\\\.\\pipe\\AgentIpcChannel");

        return s_http_response::ok({
            {"pipe_name", pname},
            {"messages", nlohmann::json::array({
                {{"direction", "WRITE"}, {"size", 32}, {"ascii", "PING_COMMAND_PACKET_001"}}
            })}
        });
    });

    // POST /api/pipe_intercept/clear
    router.post("/api/pipe_intercept/clear", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "PIPE_LOGS_CLEARED"}
        });
    });
}

} // namespace handlers
