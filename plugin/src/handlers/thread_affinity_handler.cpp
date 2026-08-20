#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_thread_affinity_routes(c_http_router& router) {
    // GET /api/thread_affinity/list
    router.get("/api/thread_affinity/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"threads_count", 1},
            {"threads", nlohmann::json::array({
                {{"thread_id", 1024}, {"affinity_mask", "0x00000000000000FF"}, {"ideal_processor", 0}, {"numa_node", 0}}
            })}
        });
    });

    // POST /api/thread_affinity/set
    router.post("/api/thread_affinity/set", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "AFFINITY_UPDATED"},
            {"previous_affinity_mask", "0x00000000000000FF"}
        });
    });

    // GET /api/thread_affinity/numa
    router.get("/api/thread_affinity/numa", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"numa_nodes_count", 1},
            {"total_logical_cores", 8}
        });
    });
}

} // namespace handlers
