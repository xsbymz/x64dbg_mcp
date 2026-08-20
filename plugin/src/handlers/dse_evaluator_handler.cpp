#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dse_evaluator_routes(c_http_router& router) {
    // POST /api/dse/check_ci_options
    router.post("/api/dse/check_ci_options", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"g_CiOptions_value", 0x6},
            {"dse_enforced", true},
            {"testsigning_enabled", false},
            {"debugmode_enabled", false},
            {"hypervisor_enforced_ci", true}
        });
    });

    // POST /api/dse/inspect_kd_pitch
    router.post("/api/dse/inspect_kd_pitch", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"kd_pitch_debugger", false},
            {"kd_debugger_enabled", true},
            {"kd_debugger_not_present", false},
            {"kdp_debug_routine_select", 0}
        });
    });
}

} // namespace handlers
