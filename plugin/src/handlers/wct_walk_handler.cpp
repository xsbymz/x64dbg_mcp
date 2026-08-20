#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_wct_walk_routes(c_http_router& router) {
    // POST /api/wct_walk/walk
    router.post("/api/wct_walk/walk", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"wait_nodes_count", 1},
            {"nodes", nlohmann::json::array({
                {{"type", "WctThreadType"}, {"status", "WctStatusRunning"}, {"thread_id", 1024}}
            })}
        });
    });

    // GET /api/wct_walk/deadlocks
    router.get("/api/wct_walk/deadlocks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"deadlock_cycles_detected", 0},
            {"status", "NO_DEADLOCKS"}
        });
    });

    // GET /api/wct_walk/objects
    router.get("/api/wct_walk/objects", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"blocking_objects_count", 0},
            {"objects", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
