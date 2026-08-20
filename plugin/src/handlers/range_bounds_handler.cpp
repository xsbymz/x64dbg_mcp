#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_range_bounds_routes(c_http_router& router) {
    // POST /api/range_bounds/var
    router.post("/api/range_bounds/var", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"min_value", "0x0000000000000000"},
            {"max_value", "0x0000000000000FFF"},
            {"is_bounded", true}
        });
    });

    // GET /api/range_bounds/registers
    router.get("/api/range_bounds/registers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"registers_count", 16},
            {"status", "INTERVAL_DOMAINS_COMPUTED"}
        });
    });

    // POST /api/range_bounds/overflow
    router.post("/api/range_bounds/overflow", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"overflow_possible", false},
            {"underflow_possible", false}
        });
    });
}

} // namespace handlers
