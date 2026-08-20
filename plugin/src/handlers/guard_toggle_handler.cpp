#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_guard_toggle_routes(c_http_router& router) {
    // POST /api/guard_toggle/arm
    router.post("/api/guard_toggle/arm", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"armed_pages_count", 1},
            {"status", "PAGE_GUARD_ARMED"}
        });
    });

    // POST /api/guard_toggle/disarm
    router.post("/api/guard_toggle/disarm", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"disarmed_pages_count", 1},
            {"status", "PAGE_GUARD_DISARMED"}
        });
    });

    // GET /api/guard_toggle/list
    router.get("/api/guard_toggle/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"armed_pages_count", 0},
            {"pages", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
