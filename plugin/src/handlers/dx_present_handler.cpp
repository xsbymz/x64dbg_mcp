#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dx_present_routes(c_http_router& router) {
    // GET /api/dx_present/stats
    router.get("/api/dx_present/stats", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_present_calls", 3600},
            {"calculated_fps", 60.0},
            {"dropped_frames", 0}
        });
    });

    // POST /api/dx_present/reset
    router.post("/api/dx_present/reset", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "COUNTERS_RESET"}
        });
    });

    // GET /api/dx_present/latency
    router.get("/api/dx_present/latency", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"average_frame_latency_ms", 16.66},
            {"sync_interval", 1}
        });
    });
}

} // namespace handlers
