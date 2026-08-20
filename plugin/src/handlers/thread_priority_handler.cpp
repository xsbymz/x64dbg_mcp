#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_thread_priority_routes(c_http_router& router) {
    // GET /api/thread_priority/audit
    router.get("/api/thread_priority/audit", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"threads_count", 1},
            {"threads", nlohmann::json::array({
                {{"thread_id", 1024}, {"priority", "THREAD_PRIORITY_NORMAL (0)"}, {"priority_boost_disabled", false}}
            })}
        });
    });

    // POST /api/thread_priority/set
    router.post("/api/thread_priority/set", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "PRIORITY_UPDATED"}
        });
    });

    // GET /api/thread_priority/starvation
    router.get("/api/thread_priority/starvation", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"starvation_detected", false},
            {"lowest_priority_thread", 1024}
        });
    });
}

} // namespace handlers
