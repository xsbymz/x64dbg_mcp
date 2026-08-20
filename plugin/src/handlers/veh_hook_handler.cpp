#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_veh_hook_routes(c_http_router& router) {
    // GET /api/veh_hook/invocations
    router.get("/api/veh_hook/invocations", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"invocations_count", 0},
            {"invocations", nlohmann::json::array()}
        });
    });

    // POST /api/veh_hook/filter
    router.post("/api/veh_hook/filter", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string code = body.value("exception_code", "0xC0000005");

        return s_http_response::ok({
            {"filter_applied", code},
            {"matching_invocations", 0}
        });
    });

    // POST /api/veh_hook/clear
    router.post("/api/veh_hook/clear", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "VEH_INVOCATIONS_CLEARED"}
        });
    });
}

} // namespace handlers
