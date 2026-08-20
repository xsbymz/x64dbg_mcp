#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_mitigations_routes(c_http_router& router) {
    // GET /api/mitigations/all
    router.get("/api/mitigations/all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dep_enabled", true},
            {"aslr_bottom_up", true},
            {"aslr_high_entropy", true},
            {"cfg_enabled", true},
            {"acg_enabled", false},
            {"cet_user_shadow_stack", false},
            {"strict_handle_checks", true}
        });
    });

    // GET /api/mitigations/acg
    router.get("/api/mitigations/acg", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"acg_arbitrary_code_guard_active", false},
            {"allow_dynamic_code_generation", true}
        });
    });

    // GET /api/mitigations/shadow_stack
    router.get("/api/mitigations/shadow_stack", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"user_shadow_stack_active", false},
            {"user_shadow_stack_strict_mode", false}
        });
    });
}

} // namespace handlers
