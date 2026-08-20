#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rtl_dispatch_routes(c_http_router& router) {
    // POST /api/rtl_dispatch/simulate
    router.post("/api/rtl_dispatch/simulate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"simulated_handlers_count", 3},
            {"handling_frame", "0x00007FF712341000"},
            {"disposition", "ExceptionExecuteHandler"}
        });
    });

    // POST /api/rtl_dispatch/order
    router.post("/api/rtl_dispatch/order", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"dispatch_order", nlohmann::json::array({
                "VEH Handler 1 (0x7FF712001000)",
                "Frame Handler 0 (0x7FF712341050)",
                "Frame Handler 1 (0x7FF712342000)"
            })}
        });
    });

    // GET /api/rtl_dispatch/collided
    router.get("/api/rtl_dispatch/collided", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"collided_unwind_detected", false}
        });
    });
}

} // namespace handlers
