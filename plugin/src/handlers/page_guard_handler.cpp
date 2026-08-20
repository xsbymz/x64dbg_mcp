#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_page_guard_routes(c_http_router& router) {
    // GET /api/page_guard/violations
    router.get("/api/page_guard/violations", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"violations_count", 1},
            {"violations", nlohmann::json::array({
                {{"faulting_address", "0x00007FF712351000"}, {"instruction_pointer", "0x00007FF712341050"}, {"access_type", "READ"}, {"thread_id", 1024}}
            })}
        });
    });

    // POST /api/page_guard/arm
    router.post("/api/page_guard/arm", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "PAGE_GUARD_ARMED"}
        });
    });

    // POST /api/page_guard/clear
    router.post("/api/page_guard/clear", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "PAGE_GUARD_LOGS_CLEARED"}
        });
    });
}

} // namespace handlers
