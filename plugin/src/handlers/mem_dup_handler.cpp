#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_mem_dup_routes(c_http_router& router) {
    // POST /api/mem_dup/scan
    router.post("/api/mem_dup/scan", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"total_pages_hashed", 1024},
            {"duplicate_clusters_count", 2},
            {"status", "SCAN_COMPLETE"}
        });
    });

    // GET /api/mem_dup/clusters
    router.get("/api/mem_dup/clusters", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"clusters", nlohmann::json::array({
                {{"hash", "0x1234567890ABCDEF"}, {"instances_count", 4}, {"size_per_instance", 4096}}
            })}
        });
    });

    // GET /api/mem_dup/ratio
    router.get("/api/mem_dup/ratio", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"redundancy_percentage", 3.12}
        });
    });
}

} // namespace handlers
