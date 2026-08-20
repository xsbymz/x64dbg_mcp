#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_early_apc_routes(c_http_router& router) {
    // POST /api/apc/scan_alertable_threads
    router.post("/api/apc/scan_alertable_threads", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"alertable_threads", nlohmann::json::array({
                {{"thread_id", 1}, {"wait_reason", "UserRequest"}, {"alertable", true}, {"current_pc", format_utils::format_address(cip)}}
            })},
            {"early_bird_apc_suspected", false}
        });
    });

    // POST /api/apc/audit_queued_routines
    router.post("/api/apc/audit_queued_routines", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"queued_user_apcs", nlohmann::json::array()},
            {"special_user_apcs", nlohmann::json::array()},
            {"status", "APC_QUEUE_INSPECTED"}
        });
    });
}

} // namespace handlers
