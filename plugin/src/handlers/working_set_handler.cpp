#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_working_set_routes(c_http_router& router) {
    // POST /api/working_set/snapshot
    router.post("/api/working_set/snapshot", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"snapshot_id", "ws_snap_01"},
            {"total_pages", 1024},
            {"working_set_bytes", 4194304},
            {"status", "WORKING_SET_CAPTURED"}
        });
    });

    // POST /api/working_set/diff
    router.post("/api/working_set/diff", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"added_pages_count", 4},
            {"removed_pages_count", 0},
            {"working_set_growth_bytes", 16384}
        });
    });

    // GET /api/working_set/pages
    router.get("/api/working_set/pages", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"private_pages", 768},
            {"shared_pages", 256}
        });
    });
}

} // namespace handlers
