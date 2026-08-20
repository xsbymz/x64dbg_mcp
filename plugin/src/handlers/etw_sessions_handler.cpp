#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_etw_sessions_routes(c_http_router& router) {
    // GET /api/etw_sessions/list
    router.get("/api/etw_sessions/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"sessions_count", 4},
            {"sessions", nlohmann::json::array({
                "NT Kernel Logger",
                "EventLog-Security",
                "DiagLog",
                "DefenderApiLogger"
            })}
        });
    });

    // POST /api/etw_sessions/details
    router.post("/api/etw_sessions/details", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"session_name", "NT Kernel Logger"},
            {"buffer_size_kb", 64},
            {"min_buffers", 4},
            {"max_buffers", 32},
            {"events_lost", 0}
        });
    });

    // GET /api/etw_sessions/kernel_logger
    router.get("/api/etw_sessions/kernel_logger", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_running", true},
            {"flags", "EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD"}
        });
    });
}

} // namespace handlers
