#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_acg_check_routes(c_http_router& router) {
    // GET /api/acg_check/status
    router.get("/api/acg_check/status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"acg_enabled", false},
            {"dynamic_code_prohibited", false},
            {"thread_opt_out_allowed", true}
        });
    });

    // GET /api/acg_check/test
    router.get("/api/acg_check/test", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rwx_allocation_allowed", true},
            {"virtual_protect_rx_to_rwx_allowed", true}
        });
    });

    // GET /api/acg_check/mitigations
    router.get("/api/acg_check/mitigations", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"ProcessDynamicCodePolicy", "DYNAMIC_CODE_POLICY_DISABLED"}
        });
    });
}

} // namespace handlers
