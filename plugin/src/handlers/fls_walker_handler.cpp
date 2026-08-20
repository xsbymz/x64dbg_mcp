#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_fls_walker_routes(c_http_router& router) {
    // GET /api/fls_walker/all
    router.get("/api/fls_walker/all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_fls_slots_allocated", 8},
            {"slots", nlohmann::json::array({
                {{"index", 0}, {"value", "0x00007FF712341000"}, {"description", "CRT Fiber Context"}},
                {{"index", 1}, {"value", "0x0000000000000000"}, {"description", "Empty"}}
            })}
        });
    });

    // POST /api/fls_walker/read_slot
    router.post("/api/fls_walker/read_slot", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int idx = body.value("slot_index", 0);

        return s_http_response::ok({
            {"slot_index", idx},
            {"slot_value", "0x00007FF712341000"}
        });
    });

    // GET /api/fls_walker/indices
    router.get("/api/fls_walker/indices", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"indices", nlohmann::json::array({0, 1, 2, 3})}
        });
    });
}

} // namespace handlers
