#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_fiber_switch_routes(c_http_router& router) {
    // POST /api/fiber_switch/current
    router.post("/api/fiber_switch/current", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"current_fiber_ptr", "0x0000000000000000"},
            {"is_thread_a_fiber", false}
        });
    });

    // POST /api/fiber_switch/list
    router.post("/api/fiber_switch/list", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"fibers_count", 0},
            {"fibers", nlohmann::json::array()}
        });
    });

    // POST /api/fiber_switch/inspect
    router.post("/api/fiber_switch/inspect", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"fiber_data", "0x0000000000000000"},
            {"stack_base", "0x0000000000130000"},
            {"stack_limit", "0x0000000000120000"}
        });
    });
}

} // namespace handlers
