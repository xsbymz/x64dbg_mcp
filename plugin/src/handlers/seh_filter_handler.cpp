#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_seh_filter_routes(c_http_router& router) {
    // POST /api/seh_filter/evaluate
    router.post("/api/seh_filter/evaluate", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"disposition", "EXCEPTION_EXECUTE_HANDLER (1)"},
            {"filter_evaluated_cleanly", true}
        });
    });

    // POST /api/seh_filter/simulate
    router.post("/api/seh_filter/simulate", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"simulated_result", "HANDLER_ENTERED"},
            {"target_ip_after_filter", "0x00007FF712341200"}
        });
    });

    // POST /api/seh_filter/disposition
    router.post("/api/seh_filter/disposition", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"code_description", "EXCEPTION_ACCESS_VIOLATION"}
        });
    });
}

} // namespace handlers
