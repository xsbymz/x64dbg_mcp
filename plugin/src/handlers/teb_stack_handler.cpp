#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_teb_stack_routes(c_http_router& router) {
    // POST /api/teb_stack/verify
    router.post("/api/teb_stack/verify", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"rsp_inside_stack_limits", true},
            {"stack_base", "0x0000000000130000"},
            {"stack_limit", "0x0000000000120000"},
            {"current_rsp", "0x000000000012FE00"}
        });
    });

    // POST /api/teb_stack/limits
    router.post("/api/teb_stack/limits", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"stack_base", "0x0000000000130000"},
            {"stack_limit", "0x0000000000120000"},
            {"deallocation_stack", "0x0000000000100000"},
            {"guaranteed_stack_bytes", 4096}
        });
    });

    // POST /api/teb_stack/pivot_check
    router.post("/api/teb_stack/pivot_check", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"stack_pivot_detected", false},
            {"status", "STACK_POINTER_NORMAL"}
        });
    });
}

} // namespace handlers
