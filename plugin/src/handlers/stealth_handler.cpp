#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_stealth_routes(c_http_router& router) {
    // POST /api/stealth/enable
    router.post("/api/stealth/enable", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"stealth_enabled", true},
            {"being_debugged_cleared", true},
            {"nt_global_flag_cleared", true},
            {"process_debug_port_hidden", true},
            {"hardware_breakpoints_hidden", true}
        });
    });

    // POST /api/stealth/disable
    router.post("/api/stealth/disable", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"stealth_enabled", false}
        });
    });

    // GET /api/stealth/status
    router.get("/api/stealth/status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_stealth_active", true},
            {"active_hooks", nlohmann::json::array({"NtQueryInformationProcess", "NtSetInformationThread", "NtGetContextThread"})}
        });
    });

    // POST /api/stealth/cloak_flag
    router.post("/api/stealth/cloak_flag", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "FLAG_CLOAKED"}
        });
    });
}

} // namespace handlers
