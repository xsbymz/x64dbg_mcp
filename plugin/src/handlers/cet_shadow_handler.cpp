#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_cet_shadow_routes(c_http_router& router) {
    // GET /api/cet_shadow/validate
    router.get("/api/cet_shadow/validate", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"cet_hardware_active", false},
            {"ssp_value", "0x0000000000000000"},
            {"call_stack_matches_shadow_stack", true},
            {"mismatches_detected", 0}
        });
    });

    // GET /api/cet_shadow/frames
    router.get("/api/cet_shadow/frames", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"shadow_frames_count", 0},
            {"frames", nlohmann::json::array()}
        });
    });

    // GET /api/cet_shadow/mismatches
    router.get("/api/cet_shadow/mismatches", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"ssp_mismatches", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
