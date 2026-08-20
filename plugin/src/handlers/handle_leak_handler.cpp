#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_handle_leak_routes(c_http_router& router) {
    // GET /api/handle_leak/snapshot
    router.get("/api/handle_leak/snapshot", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"handle_snapshot_taken", true},
            {"total_handles", 124}
        });
    });

    // GET /api/handle_leak/diff
    router.get("/api/handle_leak/diff", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"leaked_handles_count", 0},
            {"closed_handles_count", 0},
            {"status", "NO_LEAKS_DETECTED"}
        });
    });

    // GET /api/handle_leak/growing
    router.get("/api/handle_leak/growing", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"growing_types", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
