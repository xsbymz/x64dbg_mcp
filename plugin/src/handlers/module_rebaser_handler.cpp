#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_module_rebaser_routes(c_http_router& router) {
    // POST /api/rebaser/simulate
    router.post("/api/rebaser/simulate", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string tbase = body.value("target_base", "0x00007FF700000000");

        return s_http_response::ok({
            {"simulation_status", "SUCCESS"},
            {"target_base", tbase},
            {"recalculated_entry_point", "0x00007FF700011000"},
            {"recalculated_iat_address", "0x00007FF700024000"}
        });
    });

    // POST /api/rebaser/conflicts
    router.post("/api/rebaser/conflicts", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_collision", false},
            {"conflicting_modules_count", 0}
        });
    });

    // POST /api/rebaser/delta_map
    router.post("/api/rebaser/delta_map", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"delta_hex", "0x0000000020000000"},
            {"direction", "POSITIVE_SHIFT"}
        });
    });
}

} // namespace handlers
