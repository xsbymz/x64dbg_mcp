#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_deadlock_routes(c_http_router& router) {
    // GET /api/deadlock/scan
    router.get("/api/deadlock/scan", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"deadlock_detected", false},
            {"sync_objects_analyzed", 6},
            {"threads_analyzed", 4}
        });
    });

    // GET /api/deadlock/sync_objects
    router.get("/api/deadlock/sync_objects", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"objects", nlohmann::json::array({
                {{"type", "CRITICAL_SECTION"}, {"address", "0x00007FF712354000"}, {"lock_count", 0}, {"owner_tid", 0}},
                {{"type", "MUTEX"}, {"address", "0x0000000000000088"}, {"name", "Global\\AppSingleInstanceMutex"}, {"owner_tid", 1024}}
            })}
        });
    });

    // GET /api/deadlock/wait_chains
    router.get("/api/deadlock/wait_chains", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"wait_chains_count", 0},
            {"chains", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
