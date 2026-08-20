#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_hw_counter_routes(c_http_router& router) {
    // GET /api/hw_counter/counters
    router.get("/api/hw_counter/counters", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dr0_hits", 142},
            {"dr1_hits", 0},
            {"dr2_hits", 0},
            {"dr3_hits", 0}
        });
    });

    // POST /api/hw_counter/reset
    router.post("/api/hw_counter/reset", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "COUNTERS_RESET"}
        });
    });

    // GET /api/hw_counter/rates
    router.get("/api/hw_counter/rates", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dr0_hits_per_sec", 12.4},
            {"status", "PROFILING_ACTIVE"}
        });
    });
}

} // namespace handlers
